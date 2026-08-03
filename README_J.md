<div align="center">
    <img src="./design/logo.svg" width="12%" height="12%" alt="qanvuli logo">
</div>

# qanvuli

qanvuli は、ローカルの脆弱性データベースを構築・検索するツールです。CVE List のデータに CWE、CAPEC、OSV、CISA KEV、FIRST EPSS の情報を組み合わせ、SQLite に格納します。

CLI、ターミナル UI、Rust API、MCP サーバーを提供します。各データソースを取り込んだ後の検索は、ローカル環境で実行されます。

## 機能

- CVE の全件アーカイブと選択した補足データからデータベースを構築
- CVE の差分と OSV の増分更新を適用
- CVE レコードを識別子、テキスト、影響を受ける製品、CWE、CAPEC、CVSS、日付で検索し、OSV アドバイザリをテキストで検索
- 対応する OSV と CVE List のバージョン範囲に基づき、パッケージのバージョンが影響を受けるか判定
- ターミナル UI で CVE、OSV、CWE、CAPEC のデータを閲覧
- GitHub の依存関係グラフから出力した SBOM と、SPDX または CycloneDX 形式の SBOM JSON をローカルの脆弱性データでスキャン
- 検索、補足情報の取得、保守操作を MCP 経由で提供

## 動作要件

- Rust 2024 Edition に対応する Rust ツールチェーン
- データソースをダウンロードするためのネットワーク接続
- CVE アーカイブの展開とデータベースの保存に必要な空き容量

既定では、カレントディレクトリの `db.sqlite` を使用します。

```text
sqlite://./db.sqlite?mode=rwc
```

保存先は `--db-url` または `QANVULI_DB_URL` で変更できます。

## インストール

```bash
cargo install --path . --locked
qanvuli --help
```

開発時は、次のように実行できます。

```bash
cargo run -- --help
```

## 初期化と更新

最新のデータソースから置換用データベースを構築します。

```bash
qanvuli init
```

既存の CVE アーカイブを使用する場合や、使用するディスク容量のピークを抑える場合は、次のオプションを指定します。

```bash
qanvuli init --zip ./data/all-cves.zip
qanvuli init --delete-existing
qanvuli init --no-progress
```

通常、`init` は使用中のデータベースと同じ場所に置換候補を構築し、必須スキーマと所定の検索検証項目を確認してから接続を閉じ、置換します。使用中のデータベースをロールバック用バックアップへ移動する前に WAL のチェックポイントを実行し、安全に接続を閉じられない場合は置換を中止します。構築に失敗しても、使用中のデータベースは変更されません。初期化は、SQLite を使用するほかのプロセスを停止してから実行してください。

`init --zip` で指定したアーカイブはユーザー所有のローカルファイルとして扱い、自動的には削除しません。`--keep` は、`--zip` を省略したときに自動ダウンロードされる CVE アーカイブだけに適用されます。

`--delete-existing`（`-D`）は、古い `*.qanvuli-new-*` 置換候補と使用中のデータベースを削除してから、置換データをダウンロードして構築します。使用するディスク容量のピークは抑えられますが、同時に実行中の初期化を妨げる可能性があり、その後の処理に失敗すると利用可能なデータベースは残りません。ほかに `qanvuli init` が実行されていないことを確認した場合に限り使用してください。

未適用の CVE 差分を取得して適用し、補足データを更新します。

```bash
qanvuli update
qanvuli update --osv-refresh-all
qanvuli update --no-progress
```

ローカルの CVE アーカイブを取り込む場合は、次のように指定します。

```bash
qanvuli update --zip ./data/delta.zip
```

`--zip` を指定しない場合、`update` は CVE 差分の適用後に CWE、CAPEC、保存済みの OSV 選択、KEV、EPSS を更新します。`--zip` を指定した場合は、指定した CVE アーカイブだけを取り込みます。OSV ソースのフラグも指定した場合に限り OSV を更新し、このモードでは CWE、CAPEC、KEV、EPSS を更新しません。

`update --zip` で指定したアーカイブはユーザー所有として扱い、成功時も失敗時も保持します。リモート更新では、`--keep` を指定すると自動ダウンロードした CVE 差分アーカイブを保持し、省略した場合は処理成功後に削除することがあります。

リモートの `update` は再開可能ですが、すべてのリモートソースを包含する単一のアトミックトランザクションではありません。後続の CWE、CAPEC、OSV、KEV、EPSS の更新に失敗しても、適用済みの CVE 差分とカーソルは保持されます。`qanvuli update` を再実行すると保存済みの状態から再開します。更新の失敗は、データがまったく変更されなかったことを意味しません。

`--osv-refresh-all` は OSV カーソルを無視し、選択したスナップショットの全件を upsert します。スナップショットに存在しない項目は削除されたものとして扱いません。撤回されたアドバイザリも、撤回日時とともに引き続き参照できます。

`init` は既定で GHSA と OSV（OSS-Fuzz）を取り込みます。`--osv-rustsec` や `--osv-pysec` などのフラグでソースを追加でき、`--osv-all` ですべてのソースを選択できます。`update` は `init` が保存した選択を再利用し、指定されたソースのフラグがあれば追加します。全項目は `qanvuli init --help` で確認してください。

データベースを変更せずに CVE アーカイブをダウンロードするには、次のコマンドを実行します。

```bash
qanvuli download-cve --kind delta --output-dir ./data
qanvuli download-cve --kind all --output-dir ./data
```

## 検索

```bash
qanvuli search --text openssl --limit 20
qanvuli search --source osv --text openssl
qanvuli search --cwe CWE-79
qanvuli search --capec CAPEC-63
qanvuli search --vendor microsoft --product windows
qanvuli search --min-score 9.0 --severity CRITICAL
qanvuli search --cve CVE-2024-12345
```

CWE と CAPEC のカタログを検索・参照するには、次のコマンドを実行します。

```bash
qanvuli cwe cross-site --status Stable
qanvuli cwe --id CWE-79 --detail
qanvuli capec phishing --type Standard
qanvuli capec --id CAPEC-98 --detail
```

複数のデータソースを横断して検索するには、次のコマンドを実行します。

```bash
qanvuli query resolve --id CVE-2024-12345
qanvuli query enriched-cve --id CVE-2024-12345
qanvuli query package --ecosystem crates.io --name time --version 0.1.0
```

`query package` は、対応する OSV のバージョン範囲をエコシステム固有の規則で判定します。判定できない場合や結果が曖昧な場合は、確認済みの検出結果に含めず、要確認として返します。

整形済みの JSON を出力するには `--pretty` を指定します。

## データベースの保守

```bash
qanvuli db status
qanvuli db check
qanvuli db check --scan
qanvuli db check --full
qanvuli db rebuild-search
```

`db check` はスキーマと所定の検索検証項目を確認します。`--scan` を指定すると、SQLite、外部キー、FTS、プロジェクションの検査も行います。`--full` は、最も処理負荷の高い整合性検査を実行します。

取り込んだ OSV の関連情報から、データソースを横断する識別子のリンクを再構築します。

```bash
qanvuli graph rebuild
```

データベースファイルは、元データから生成される成果物です。未対応のスキーマをその場で修正することはありません。`qanvuli init` で再構築してください。

## ターミナル UI

```bash
qanvuli tui
qanvuli tui openssl
```

主なキー操作は次のとおりです。

- `Enter`: 検索
- `Tab`: ペインの切り替え
- `/`: 詳細内の検索
- `F1`: ヘルプ
- `F2`: 検索モードの切り替え
- `F3`: 詳細検索
- `F4`: 表示設定またはカタログの絞り込み
- `F5`: データベースの保守
- `F8`: CVE または OSV の未加工 JSON
- `F9`: CWE カタログ
- `F10`: CAPEC カタログ
- `Esc`: ポップアップを閉じる、または現在のモードを終了
- `Ctrl-C`: 終了

## SBOM 検索

```bash
qanvuli sbom ./sbom.json
qanvuli sbom --file ./sbom.json --per-package-limit 5
qanvuli sbom ./sbom.json --sarif-output ./qanvuli.sarif
```

`sbom` は、GitHub の依存関係グラフから出力した SBOM と、SPDX または CycloneDX 形式の JSON を読み込みます。CycloneDX のトップレベル `components`、ルートの `metadata.component`、および両者の配下に入れ子になったコンポーネントに対応します。PURL があるパッケージは、crates.io／Cargo、Go、GitHub Actions、Maven、npm、NuGet、PyPI、Pub、RubyGems 専用のバージョン規則を用いて OSV と CVE List のデータに照合します。バージョンがない場合、バージョン方式に対応していない場合、判定が曖昧な場合は、確認済みの検出結果に含めず、要確認として返します。パッケージ名のみが一致する CVE は任意の候補として扱われ、脆弱性が確認された件数には含まれません。

JSON は従来どおり標準出力へ出力します。`--sarif-output <PATH>` を指定すると、同じスキャン結果をコードスキャン連携用の SARIF 2.1.0 ファイルにも同時出力します。

## MCP サーバー

```bash
qanvuli mcp
```

stdio サーバーは、ローカルの CVE、CWE、CAPEC、OSV、KEV、EPSS に対するクエリと、データベースの更新機能を提供します。パッケージのクエリは既定で詳細な照合根拠を省略します。一致の詳細が必要な場合に限り、根拠情報を要求してください。

パッケージの一括照会と最近の更新一覧は、判定に必要な脆弱性／要確認状態とリスク情報を保持したコンパクトな概要を既定で返します。findings、CWE、CVSS ベクトル、影響バージョンの詳細が必要なパッケージまたは CVE に限り、`verbosity="full"` を指定してください。

OSV にデータがないことは、そのパッケージに CVE が存在しないことを保証しません。重要なパッケージやサポート終了済みのパッケージについては、CVE List とベンダーのアドバイザリも確認してください。

## ワークスペース

- `app/`: CLI とユーザー向けクレート
- `collector/`: データソースのクライアント
- `core/`: このリポジトリのワークスペースまたはソースチェックアウトから利用できる Rust API
- `db/`: スキーマ、インポート、クエリ
- `models/`: 各データソースのモデル
- `utils/`: アーカイブ、GitHub、ログ、日時に関するユーティリティ

Rust API は crates.io への公開を想定したものではありません。このリポジトリのワークスペースまたはソースチェックアウトから path クレートとして利用してください。
