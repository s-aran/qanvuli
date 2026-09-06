# `qanvuli-core` API ガイド

[English](./API.md)

この文書は、`qanvuli-core` クレートが公開する Rust API だけを説明します。CLI、
TUI、MCP サーバーはこの API を利用するアプリケーションであり、本書の対象外です。

`qanvuli-core` は、qanvuli のデータベース、フィード取得、ソースモデルをまとめる
ファサードです。公開 API は4つのモジュールに分かれています。

| モジュール | 役割 |
| --- | --- |
| `qanvuli_core::database` | SQLite のライフサイクル、CVE/OSV 検索、パッケージ評価、補足情報、取り込み、安全な DB 置換 |
| `qanvuli_core::ingest` | CVE、CWE、CAPEC、OSV、KEV、EPSS の取得と CVE アーカイブの読み込み |
| `qanvuli_core::model` | CVE、CWE、CAPEC、OSV のソースモデルとカタログのパーサー |
| `qanvuli_core::runtime` | ネットワーククライアントを使う前に必要なプロセス単位の初期化 |

現時点では、このクレートをワークスペースまたはソースのチェックアウトから利用します。
crates.io 向けに SemVer 安定性を保証した API ではありません。

## クレートの追加

`core` ディレクトリをパス依存関係に指定します。

```toml
[dependencies]
qanvuli-core = { path = "../qanvuli/core" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Rust のパッケージ名にはハイフンがありますが、インポート名には
`qanvuli_core` のようにアンダースコアを使います。

## データベース API

### 接続のライフサイクル

DB ハンドルには、基本的に `CveDatabase` を使います。これは、同じく公開されている
`SqlxDatabase` の型エイリアスです。

```rust
use qanvuli_core::database::CveDatabase;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = CveDatabase::connect("sqlite://./db.sqlite?mode=rwc").await?;
    db.check_required_schema().await?;

    // ここで検索します。

    db.close().await?;
    Ok(())
}
```

接続のライフサイクルで使う主なメソッドは、次の5つです。

| メソッド | 用途 |
| --- | --- |
| `CveDatabase::connect(url)` | SQLite DB ハンドルを開きます。接続しただけでは qanvuli のスキーマを検証しません。 |
| `initialize()` / `initialize_schema()` | スキーマを作成または移行します。`initialize_schema` は `initialize` の互換用の別名です。 |
| `check_required_schema()` | 既存 DB が現在のライブラリに必要なスキーマを持つか確認します。利用者が選んだ DB を検索する前に呼び出します。 |
| `schema_version()` | このライブラリのビルドが要求するスキーマバージョンを返します。DB を開かない関連関数です。 |
| `close()` | 書き込み接続を閉じます。この呼び出しによってハンドルが消費されます。 |

DB メソッドの多くは `Result<_, sqlx::Error>` を返します。具体的なエラー型は下位の
DB クレートに由来します。ただし、呼び出し元のエラー型が標準エラーを受け入れられるなら、
上の例のように `sqlx` を直接インポートせず `?` を使えます。

### CVE の戻り値

上位の型には、公開された脆弱性 ID と正規化済みの内容だけが含まれます。SQLite の内部行
ID は含まれません。

主な戻り値の型は、次の10個です。

| 型 | 内容 |
| --- | --- |
| `CveSummary` | CVE ID、状態、公開・更新日時、タイトル、任意の英語説明 |
| `CveDetail` | `cwes`、`cvss`、`affected`、`ssvc` の各コレクション |
| `CveSummaryWithDetail` | `CveSummary` と `CveDetail` の組み合わせ |
| `CveCweDetail` | 数値 CWE ID と任意の説明 |
| `CveCvssDetail` | CVSS バージョン、基本スコア、深刻度、ベクター、情報源 |
| `CveAffectedDetail` | ベンダー、製品、パッケージ名、補足情報、影響を受けるバージョン |
| `CveAffectedVersionDetail` | バージョン、状態、バージョン形式、上限 |
| `CveReference` | 参照 URL、名前、タグ |
| `CveRiskSummary` | KEV、EPSS、最大 CVSS をまとめたトリアージ用の軽量行 |
| `SsvcInfo` | プロバイダー、ロール、バージョン、評価日時、判断項目（decision point）を持つ、取り込み済みの SSVC 評価 |

`CveSummary.state` はメモリ上では数値です。`cve_state_label(state)` を使うと、
`"PUBLISHED"`、`"REJECTED"`、`"UNKNOWN"` に変換できます。`Serialize` した
場合も、読みやすいラベルが出力されます。

`Sqlx*` 型は、DB に保存された表現に近い低レベルのプロジェクションです。保存形式をその
まま扱いたい利用者のために公開されています。ここで扱う型を、用途別の4グループに分けて
示します。

- `SqlxCveSummary`、`SqlxCveDetail`、`SqlxCveSummaryWithDetail`
- `SqlxCwe`、`SqlxCvss`、`SqlxAffected`
- `SqlxCveReference`、`SqlxEpss`、`SqlxEpssRisk`、`SqlxKev`、
  `SqlxKevEntry`
- `SqlxOsvSummary`、`SqlxDatabaseStatus`、`SqlxSourceSyncState`、
  `SqlxIdentifierResolution`、`SqlxIdentifierEdge`、`SqlxPackageFinding`

SQL プロジェクション自体を連携仕様にする必要がなければ、上位の型を優先してください。

### CVE を1件または複数件取得する

CVE の取得方法は、次の7つです。

| メソッド | 戻り値 |
| --- | --- |
| `find_cve_summary(cve_id)` | 存在すれば、軽量な `SqlxCveSummary` を1件返します。 |
| `find_cve_summary_with_detail(cve_id)` | 上位の `CveSummaryWithDetail` を1件返します。 |
| `find_cve_summary_with_detail_with_state_scope(cve_id, scope)` | 却下済みレコードを含めるか明示して、同様に1件返します。 |
| `cve_summaries_with_details_batch(ids, scope)` | 要求した ID の順序を保って一括取得します。存在しない要素や、対象範囲外の要素は `None` です。 |
| `find_cve_raw_json_by_id(cve_id)` / `cve_raw_json(cve_id)` | 保存した元の CVE JSON を返します。 |
| `find_cve_model_by_id(cve_id)` | パース済みの `RawCveStatusRecord` と元の JSON 値を返します。 |
| `find_cve_references(cve_id)` | 1件の CVE に対する正規化済みの参照情報を返します。 |

提供元固有のフィールドが必要な場合に限り、元の JSON を使ってください。通常は概要と
詳細の DTO の方が小さく、完全な CVE スキーマへの依存も避けられます。

### CVE を検索する

上位の検索メソッドは、明示的な取得上限とオフセットを受け取ります。名前が
`_with_state_scope` で終わるものは `CveStateScope` も受け取ります。

```rust
use qanvuli_core::database::{CveDatabase, CveStateScope};

async fn search(db: &CveDatabase) -> Result<(), Box<dyn std::error::Error>> {
    let rows = db
        .search_cve_summaries_free_text_with_state_scope(
            "openssl",
            CveStateScope::PublishedOnly,
            25,
            0,
        )
        .await?;

    for row in rows {
        println!("{} — {}", row.cve_id, row.title);
    }
    Ok(())
}
```

`CveStateScope::PublishedOnly` は既定値で、却下済みレコードを除外します。
却下済みレコードも必要な場合は、`CveStateScope::IncludeRejected` を明示的に選択してください。
アプリケーション境界では `CveStateScope::from_include_rejected(bool)` も利用できます。

主な検索メソッドは、次の11個です。

| メソッド | 検索仕様 |
| --- | --- |
| `search_cve_summaries_free_text_with_state_scope` | CVE ID、タイトル、英語の説明、`affected` のテキスト、インデックス登録済みの参照テキストを FTS で検索します。結果は関連度順です。 |
| `search_cve_summaries_by_cwe_with_state_scope` | 指定した CWE ID のいずれかに一致する CVE を検索します。ID は数値だけでも、`CWE-` 接頭辞付きでも指定できます。 |
| `search_cve_summaries_by_vendor_product_with_state_scope` | 正規化済みの `affected` のベンダーと製品またはパッケージを部分一致で検索します。 |
| `search_cve_summaries_by_vendor_product_exact_with_state_scope` | `affected` の項目を完全一致または部分一致で検索します。WordPress コレクションを除外するかどうかも選べます。 |
| `search_cve_summaries_by_cvss_with_state_scope` | 両端を含むスコア範囲と、任意の深刻度および CVSS バージョンで検索します。同じメトリクス行が、すべての CVSS 条件を満たす必要があります。 |
| `search_cve_summaries_by_product_cvss_exact_with_state_scope` | `affected` 条件と CVSS 条件を AND で結合し、一致したスコアが高い順に返します。 |
| `search_cve_summaries_by_date_with_state_scope` | 公開日時と更新日時の下限を指定します。境界値も検索対象に含まれます。 |
| `search_cve_summaries_by_cve_id_prefix_with_state_scope` | CVE ID の前方一致です。 |
| `search_cve_summaries_by_reference_text` | 参照 URL、名前、タグを検索します。 |
| `search_cve_summaries_by_date_range` | 公開日時・更新日時の範囲を両端を含めて指定します。 |
| `list_recent_updates` | 任意の日時以降に更新された CVE を返します。 |

多くの検索系統には、ページネーションのメタデータを取得するための `count_*` メソッドも
あります。ページと件数の取得には、同じ対象範囲と絞り込み条件を渡してください。

ベンダーと製品の検索対象は、構造化された `affected` フィールドです。タイトルや説明文に
単語が含まれるだけでは一致しません。文章を検索する場合は全文検索メソッドを使います。

`search_cve_summaries_by_vendor_product_exact_with_state_scope` では、完全一致の値が、
同じ項目の部分一致の値より優先されます。完全一致の引数を1つでも指定すると、その呼び出しで
指定した `affected` の項目はすべて完全一致になります。ベンダーと製品を同時に絞り込む場合は、
両方を部分一致にするか、両方を完全一致にしてください。

### 複合検索

`CveAdvancedSearch` を使うと、長い位置引数を並べず、型付きのリクエストで検索できます。

```rust
use qanvuli_core::database::{
    CveAdvancedQueryMode, CveAdvancedSearch, CveDatabase, CveStateScope,
    CveSummarySortOrder,
};

async fn products(db: &CveDatabase) -> Result<(), Box<dyn std::error::Error>> {
    let request = CveAdvancedSearch {
        query: Some("openssl".to_owned()),
        query_mode: Some(CveAdvancedQueryMode::Product),
        published_from: Some("2025-01-01T00:00:00Z".to_owned()),
        state_scope: CveStateScope::PublishedOnly,
        sort_order: CveSummarySortOrder::UpdatedDesc,
        ..Default::default()
    };

    let rows = db.search_cve_summaries_advanced(&request, 25, 0).await?;
    Ok(())
}
```

`CveAdvancedQueryMode` は `query` フィールドだけの意味を決めます。指定できるモードは、
次の5つです。

| モード | `query` の意味 |
| --- | --- |
| `FreeText` | CVE の全文検索 |
| `Product` | 正規化済みの `affected` の製品に対する部分一致 |
| `Vendor` | 正規化済みの `affected` のベンダーに対する部分一致 |
| `Cwe` | CWE ID |
| `Cve` | CVE ID の接頭辞 |

`query` 以外の絞り込み条件は、次の7グループです。指定した条件は AND で結合されます。

- 公開日時の範囲
- CWE
- 製品
- ベンダー
- KEV への掲載有無
- SSVC の判断項目
- レコードの状態

`sort_order` は絞り込み条件ではなく、結果の並び順を指定します。
`product_exact` と `vendor_exact` は、それぞれ部分一致フィールドの代わりに使います。
同じ項目へ部分一致と完全一致を同時に指定しないでください。

`package_ecosystem` と `package_version` は、上位アプリケーションがリクエストを
受け渡すためのメタデータです。`search_cve_summaries_advanced` 自体は、インストール済みの
バージョンを評価しません。バージョンを考慮した照合には `query_package_matches` または
`query_package_matches_batch` を使います。

低レベルの連携には、`SqlxCveSearch` と `SqlxCvssSearch` も利用できます。
`SqlxAffectedComponentSearch` は、パッケージ検索で名前から CVE を補完するときに使う、
件数制限付きの絞り込み条件です。`vendor_like` と `product_like` は SQL LIKE パターンなので、
部分一致なら `"%openssl%"` のような値を呼び出し側で渡します。利用者の入力を公開する
API では、`CveAdvancedSearch` を優先してください。

### SSVC 評価

CVE の ADP コンテナに埋め込まれた SSVC 評価は、CVE レコードの取り込み時に
自動で抽出されます。結果は `CveDetail.ssvc` と `SqlxCveDetail.ssvc` に含まれます。
直接取得する場合は `ssvc_assessments(cve_id)`、保存されている総数を取得する場合は
`ssvc_assessment_count()` を使います。

公開されている判断項目の列挙型と値は、次の3種類です。

| 型 | バリアントと文字列表現 |
| --- | --- |
| `SsvcExploitation` | `None`（`"none"`）、`PublicPoc`（`"poc"`）、`Active`（`"active"`） |
| `SsvcAutomatable` | `No`（`"no"`）、`Yes`（`"yes"`） |
| `SsvcTechnicalImpact` | `Partial`（`"partial"`）、`Total`（`"total"`） |

各列挙型は `Display`、`FromStr`、`Serialize` を実装しています。CVE を絞り込むには、
`CveAdvancedSearch` の `ssvc_exploitation`、`ssvc_automatable`、
`ssvc_technical_impact` を指定します。複数の判断項目は AND で結合され、同じ
評価行がすべての条件を満たす必要があります。`SqlxCveSearch` を直接使う場合は、
同じ絞り込み構造を持つ `SsvcSearch` を指定できます。

### ソート

`CveSummarySortOrder` は、複合検索、明示した ID の並べ替え付き参照、OSV の
並べ替え付きメソッドで使います。並べ替えの基準は、次の5種類です。

| バリアント | 動作 |
| --- | --- |
| `PublishedAsc` / `PublishedDesc` | 公開日時で並べ、同値の場合は ID を第2キーにして順序を確定します。 |
| `UpdatedAsc` / `UpdatedDesc` | 更新日時で並べ、同値の場合は ID を第2キーにして順序を確定します。 |
| `CveIdAsc` / `CveIdDesc` | CVE は自然順です。年と可変長の通番を数値として比較するため、昇順では `CVE-2099-9999` が `CVE-2099-10000` より先です。OSV ID は辞書順です。 |
| `RelationRankAsc` / `RelationRankDesc` | 利用できる場合は、関連度または呼び出し側が指定したグラフ順で並べます。それ以外の場合は、日時と ID で順序を確定します。 |
| `ScoreAsc` / `ScoreDesc` | CVE は、保存済み CVSS 基本スコアの最大値で並べます。スコアがない項目は最後です。OSV の概要には CVSS 列がないため、ID 順になります。 |

同じ日時やスコアには安定した第2キーがあるため、オフセット方式のページネーションでも、同順位の行が
不規則に入れ替わりません。公開日時のない OSV は、昇順でも降順でも最後です。

### OSV の検索

`OsvSummary` は、上位のアドバイザリー DTO です。OSV ID、スキーマバージョン、公開・更新・撤回
日時、概要、詳細、短いパッケージ概要を持ちます。`OsvRawRecord` は、元の
JSON と任意のソースパスを持つ取り込み用の入力型です。

主な検索・取得メソッドは、次の10個です。

| メソッド | 用途 |
| --- | --- |
| `search_osv_summaries_free_text(query, limit, offset)` | アドバイザリー ID、文章、別名、エコシステム、パッケージ名、purl を検索します。 |
| `search_osv_summaries_free_text_sorted(...)` | 同じ検索に `CveSummarySortOrder` を指定します。 |
| `osv_summaries_by_ids_sorted(...)` | 明示した OSV ID の集合を指定順で読み込みます。 |
| `search_osv_summaries_by_package(query, limit, offset)` | 正規化済みの OSV パッケージ識別情報を完全一致で検索します。 |
| `search_osv_summaries_scoped*` | 任意のアドバイザリー系統とエコシステムの対象範囲に、テキスト検索またはパッケージの完全一致・部分一致を組み合わせます。 |
| `find_enriched_osv(osv_id)` / `find_osv_summary(osv_id)` | アドバイザリーの概要を1件取得します。 |
| `find_osv_raw_json_by_id(osv_id)` | 元の OSV JSON を返します。 |
| `osv_summaries_for_cve_ids(cve_ids)` | CVE ID から OSV の別名をたどります。 |
| `cve_aliases_for_osv_ids(osv_ids, scope)` | OSV ID から逆向きに CVE の別名をたどります。 |
| `osv_advisory_families()` | 取り込み済みのアドバイザリー系統の一覧を返します。 |

OSV には、正規化されたベンダーフィールドがありません。OSV の説明文をベンダーとの一致と
みなさないでください。

### CWE と CAPEC カタログ

`CweEntry` は、階層の件数と関連する CAPEC ID を持つ軽量な弱点情報です。
`CapecEntry` は、同様の攻撃パターン概要です。

CWE と CAPEC を扱う主なメソッドは、次の5つです。

| メソッド | 用途 |
| --- | --- |
| `find_cwe_entry(id)` | 軽量な CWE エントリーを1件取得します。 |
| `search_cwe_entries(query, limit)` | CWE ID と説明を検索します。 |
| `search_cwe_entries_filtered(query, limit, statuses, capec_id)` | 状態と関連 CAPEC による絞り込みを追加します。 |
| `search_capec_entries(CapecSearchFilters)` | CAPEC のテキストを、任意の状態、抽象度、CWE で検索します。 |
| `find_capec(id)` | `CapecDetail` を取得します。 |

`CapecSearchFilters` は `query`、`statuses`、`types`、`cwe_id`、`limit`、
`offset` を持ちます。CAPEC の戻り値として公開される10個の型は、次の4グループに
分かれています。

- `CapecEntry`、`CapecDetail`
- `CapecCategory`、`CapecCategoryDetail`
- `CapecView`、`CapecViewDetail`
- `CapecReference`、`CapecHistory`、`CapecNote`、`CapecTaxonomyMapping`

### 識別子、補足情報、リスク

識別子の解決、補足情報、リスク評価に使う主な API は、次の10個です。

| 関数またはメソッド | 用途 |
| --- | --- |
| `detect_identifier_type(value)` | DB を使わず、CVE または OSV 系統の識別子を分類します。 |
| `resolve_identifier(id)` | CVE、GHSA、RUSTSEC、PYSEC、GO などの保存済みの別名を、ローカルのグラフで解決します。 |
| `related_edges(id)` / `identifier_edges(id)` | グラフのエッジと根拠を返します。 |
| `get_enriched_cve(cve_id)` | CVE の詳細に、OSV の別名とパッケージ、KEV、EPSS、SSVC、情報源の鮮度を結合します。 |
| `enriched_cve_summaries(cve_ids)` | 最新の SSVC 判断項目を含む、CVE 一覧向けの軽量な補足情報を一括取得します。 |
| `cve_risk_summaries(cve_ids)` | KEV、EPSS、最大 CVSS のトリアージ行を一括取得します。 |
| `search_cve_risk_by_epss(...)` | EPSS のスコアおよびパーセンタイルと、KEV 情報で検索します。 |
| `kev_entries(...)` / `kev_entries_count()` | ローカルに取り込んだ CISA KEV を読みます。 |
| `database_status()` / `database_status_enriched()` | 基本の DB 状態、または情報源を横断した DB 状態を読み込みます。後者には SSVC 評価の件数も含まれます。 |
| `source_sync_states()` | 情報源ごとのカーソルと同期状態を読み込みます。 |

ここでよく使う公開レスポンス型は、次の5つです。

- `EnrichedCveSummary`
- `CveRiskSummary`
- `Evidence`
- `PrioritySignals`
- `FindingEnrichment`

### パッケージの識別とバージョン照合

インストール済みパッケージを1件調べるには `query_package_matches` を使います。

```rust
use qanvuli_core::database::CveDatabase;

async fn check_package(db: &CveDatabase) -> Result<(), Box<dyn std::error::Error>> {
    let findings = db
        .query_package_matches("crates.io", "time", "0.1.0", None)
        .await?;

    for finding in findings {
        println!(
            "{}: {} ({})",
            finding.primary_id,
            finding.affected.status,
            finding.affected.confidence
        );
    }
    Ok(())
}
```

`query_package_matches_batch(&[PackageQuery])` は、件数を制限した一括処理版です。
`query_package_enriched_with_evidence` は KEV、EPSS、優先度シグナルと、任意の詳細な
根拠を加えた検出結果を返します。CVE List とのパッケージ名の結合では、大文字・小文字と
一般的な区切り文字（`-`、`_`、`.`、空白）を無視します。
`has_osv_package_advisory` と一括処理版は、特定のバージョンを評価しません。ローカルの OSV
コーパスがパッケージ識別情報を扱っているかどうかを確認します。

`EnrichedFinding` は、不確実さに関する次の6項目を明示的に保持します。

- `source` と `primary_id` は、元の CVE List または OSV レコードを示します。
- `package` は入力した `PackageQuery` です。
- `affected: AffectedStatus` は、状態と信頼度を持ちます。
- `fixed_versions` は修正版を、`FindingEnrichment` は KEV/EPSS 情報を保持します。
- `PrioritySignals` は、トリアージ用に導出したシグナルを持ちます。
- `Evidence` は、パッケージ、アドバイザリー、別名の各要素が結び付いていることを示す根拠です。

未対応または曖昧な比較結果を、影響を受けることが確認済みの状態へ昇格させることはありません。

データベースモジュールには、DB を使わずに識別情報を扱う補助関数もあります。主な補助関数は、
次の7つです。

| 関数 | 用途 |
| --- | --- |
| `normalize_package_name(ecosystem, name)` | エコシステムごとのパッケージ名の識別規則を適用します。 |
| `ecosystem_identity_key(ecosystem)` | 大文字と小文字の扱いを含む、標準のエコシステムキーを作ります。 |
| `versions_equivalent(ecosystem, left, right)` | 明示的に列挙された2つのバージョンを比較します。 |
| `is_concrete_package_version(ecosystem, version)` | 制約ではなく、対応可能な具体的バージョンとして扱える文字列か判定します。 |
| `parse_package_purl(purl)` | 対応する purl をパースし、`ParsedPackagePurl` に変換します。 |
| `package_identity_purl(purl)` | バージョンを除いた標準 purl を返します。未対応の入力は変更しません。 |
| `evaluate_sqlx_osv_version(ecosystem, installed, ranges)` | `SqlxOsvRange` を評価し、`SqlxVersionMatch` を返します。 |

crates.io/Cargo、GitHub Actions、Go、Maven、npm、NuGet、PyPI、Pub、RubyGems
には専用の規則があります。未知のエコシステムでは、バージョンの意味を推測せず、厳密な
代替処理を使います。

### 取り込みと保守

DB ハンドルは、次の4種類のデータに対して、複数レベルの取り込み API を公開しています。

| 対象 | メソッド |
| --- | --- |
| CVE JSON | `import_cve_raw_json`、`import_cve_raw_jsons`、検索更新を遅延させる版、`import_cve_raw_jsons_bulk_init` |
| OSV JSON | `import_osv_record`、`import_osv_records`、遅延・増分・一括処理版 |
| CWE/CAPEC | `upsert_cwe_catalog`、`replace_capec_catalog` |
| KEV/EPSS | `import_kev_json`、`import_kev_json_with_status`、`import_epss_csv`、`import_epss_csv_with_status` |

`OsvImportStats` は `examined`、`inserted`、`updated`、`unchanged` を持ちます。
`changed()` は、inserted と updated の合計を返します。`ImportSummary` は、情報源を
横断する軽量な取り込み概要です。

一括処理 API では、データの読み込みとインデックスの保守を意図的に分けています。
関連する操作は、次の5グループです。

- `prepare_cve_bulk_load` / `finish_cve_bulk_load`
- `prepare_osv_bulk_load` / `finish_osv_bulk_load`
- `rebuild_cve_search`、`rebuild_osv_search`、`rebuild_search`
- `refresh_cve_search_for_ids`
- `rebuild_identifier_graph`

`prepare_*` と `finish_*` の間で処理を放置しないでください。その間は検索インデックスが
意図的に未完成な場合があります。

整合性検査は、コストが異なる次の5段階に分かれています。

| メソッド | 検査範囲 |
| --- | --- |
| `check()` | 必須スキーマと、範囲を限定した検索整合性の確認 |
| `check_scan()` | SQLite の簡易検査、外部キーの対応関係、より広範な検索走査 |
| `check_full_sqlite()` | SQLite の完全性検査 |
| `check_full_foreign_keys()` | 外部キーの完全検証 |
| `check_full_cve_search()` / `check_full_osv_search()` | 検索プロジェクションの完全検証 |

## 安全な DB 置換

置換 API は、構築・クローズ・事前検証を済ませた SQLite の置換候補を、稼働中の DB
と同じディレクトリで入れ替えます。

安全な置換に使う API は、次の9個です。

| 要素 | 用途 |
| --- | --- |
| `candidate_database_path(target)` | 置換対象と同じディレクトリに、一意な置換候補のパスを作ります。 |
| `DatabaseReplacement::new(target, candidate)` | 同一ディレクトリでの置換処理を準備します。 |
| `install()` | 置換対象をチェックポイント処理して閉じ、ロールバック用のバックアップへ移してから、置換候補を設置します。 |
| `rollback()` | 置換候補の設置が完了する前に、保留中のバックアップを復元します。状態に制約があるため、設置に成功した後は `commit()` へ進みます。 |
| `commit()` | 正常に設置できた後で、バックアップを削除します。 |
| `backup_path()` | 生成されたバックアップのパスを確認します。 |
| `recover_interrupted_replacement(target)` | 範囲を限定した復旧規則を実行し、`RecoveryAction` を返します。 |
| `remove_sqlite_database_files(path)` | SQLite のメインファイルと WAL、SHM、journal のサイドカーファイルを削除します。 |
| `remove_interrupted_replacement_candidates(target)` | qanvuli の命名規則に沿う置換候補を削除します。別のプロセスが所有している可能性があるため、呼び出し側で利用者の確認が必要です。 |

失敗は `ReplacementError` で表現されます。状態が曖昧な場合は、ファイルを推測で選んで
破壊的な操作を行わず、手作業での確認が必要なエラーを返します。

## 取り込み API

ネットワークを使う収集処理の前に、プロセスの起動時に
`runtime::init_tls_provider()` を1回呼びます。何度呼んでも安全です。

```rust
use qanvuli_core::{
    ingest::CveRelease,
    runtime::init_tls_provider,
};

async fn newest_cve_archive() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_tls_provider();

    let mut releases = CveRelease::new();
    releases.refresh().await?;
    if let Some(asset) = releases.latest_full_asset() {
        println!("{} ({} bytes)", asset.name, asset.size);
    }
    Ok(())
}
```

### フィード取得

フィードの取得に使う型、関数、定数は、次の10個です。

| 要素 | 用途 |
| --- | --- |
| `CveRelease` | CVEProject の GitHub リリースを更新し、全件、差分、日次（end-of-day）、カーソル以降の各アセットを選びます。 |
| `GitHubReleaseFile` | リリースアセットのメタデータと、非同期またはブロッキング方式でバイト列やファイルをダウンロードするメソッドを提供します。`safe_file_name()` は、ローカルへ保存する前にアセット名を検証します。 |
| `CweCatalogFile` | ETag と Last-Modified を使って CWE カタログを条件付きでダウンロードします。 |
| `CapecCatalogFile` | 呼び出し側が選んだパスへ CAPEC カタログを条件付きでダウンロードします。 |
| `OsvGcsSource` | `all.zip`、情報源の系統別 zip、`modified_id.csv`、個別のアドバイザリー JSON を読み込む、公開 OSV バケットのクライアントです。 |
| `OsvDownloadError` | ローカルストレージの障害と、ネットワークまたはレスポンスの障害を区別します。`is_local_storage()` は、保存先を切り替えるかどうかの判断に使えます。 |
| `OsvModifiedId` / `parse_modified_id_csv` | OSV の増分カーソル行をパースします。 |
| `download_kev_json()` | 現在の CISA KEV JSON を文字列で取得します。 |
| `download_epss_current_csv()` | 現在の FIRST EPSS CSV を取得・展開して文字列で返します。 |
| `OSV_ALL_ZIP` | 公開 OSV 全件アーカイブのオブジェクト名 |

### アーカイブ読み込み

`JsonStorage` は、CVE JSON 情報源の共通インターフェースです。`read_bytes`、
`read_entry`、`read_string`、`paths`、`entries` を提供します。

`ZipStorage::new(path)` は CVE アーカイブを開き、対応する入れ子の zip 形式も処理します。
`JsonEntry` は、アーカイブ内のエントリーを表します。大きな入れ子のアーカイブでは、
`ZipStorage` が一時展開ディレクトリを使う場合があります。`extracted_dir()` で確認し、
`retain_extracted_dir()` で保持するか、`cleanup_extracted_dir()` で明示的に削除できます。

## ソースモデルと CVSS API

`model` モジュールは、情報源レベルのモデル、カタログのパーサー、CVSS ベクターの補助機能を
公開しています。

公開される主な要素は、次の9個です。

| 要素 | 用途 |
| --- | --- |
| `RawCveStatusRecord` | パース済みの公開済みまたは却下済み CVE と、元の JSON 値の組み合わせ |
| `WeaknessCatalog` | MITRE CWE カタログの完全なモデル |
| `AttackPatternCatalog` | MITRE CAPEC カタログの完全なモデル |
| `read_cwe_catalog_zip(path)` | CWE の zip 内にある XML を読み取り、パースします。 |
| `read_capec_catalog_xml(path)` | CAPEC の XML ファイルを読み取り、パースします。 |
| `OSV_DATABASE_SOURCE_PREFIXES` | 既知の OSV 情報源 DB の接頭辞 |
| `is_known_osv_database_prefix(prefix)` | OSV 情報源の接頭辞を、大文字と小文字を区別せずに検証します。 |
| `score_cvss_vector(vector)` | CVSS v2.0、v3.0、v3.1、v4.0 のベクターを検証し、基本スコアと深刻度を計算します。 |
| `explain_cvss_vector(version, vector)` | ベクターの略号を、表示用のメトリクス名と値に展開します。 |

```rust
use qanvuli_core::model::{explain_cvss_vector, score_cvss_vector};

fn inspect_vector() -> Result<(), String> {
    let vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L";
    let score = score_cvss_vector(vector)?;
    println!("CVSS {}: {} {}", score.version, score.score, score.severity);

    for metric in explain_cvss_vector(&score.version, vector) {
        println!("{}: {}", metric.name, metric.value);
    }
    Ok(())
}
```

`score_cvss_vector` は `CvssScore` を返します。未対応のバージョン、不正なベクター、
必須メトリクスの不足、メトリクスの重複はエラーです。CVSS v2.0 に限り、
`CVSS:2.0/` ヘッダーを省略できます。それ以降のバージョンではヘッダーが必要です。

`explain_cvss_vector` は、表示用の `Vec<CvssVectorMetric>` を返します。ベクター内に
バージョンがあれば `version` 引数より優先し、ヘッダーのないベクターでは引数を代替値
として使います。この関数は、ベクターの検証やスコア計算を行いません。未知のメトリクス
名や値は、元のテキストのまま保持します。

ソースモデルは、DB 検索用の軽量 DTO ではありません。取り込みやカタログ変換には
ソースモデルを使い、通常の検索結果には `CveSummary`、`CweEntry`、`CapecEntry` を
使います。

## API 設計上の注意

API を利用する際の注意点は、次の4つです。

- 新しいコードでは、`CveDatabase`、上位の概要・詳細 DTO、型付きのオプション構造を
  優先します。`Sqlx*` は、下位のプロジェクションが必要な連携向けです。
- 一覧検索では、取得上限とオフセットも API の規約に含まれます。ページングする前に、
  結果の順序を一意に決められる並び順を選んでください。
- OSV パッケージ検索の結果が空であることは、ローカルに取り込んだ OSV コーパスの範囲だけを表します。
  CVE やベンダーのアドバイザリーが存在しないことの証明にはなりません。
- DB ファイルは、再生成可能な成果物として扱います。互換性のないスキーマを直接編集せず、
  再構築してください。
