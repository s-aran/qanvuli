<div align="center">
    <img src="./design/logo.svg" width="21%" height="21%" alt="qanvuli logo">
</div>

# qanvuli

qanvuli は、脆弱性データベースをローカルに構築し、検索するためのツールです。CVE List のデータに CWE、CAPEC、OSV、CISA KEV、FIRST EPSS の情報を組み合わせ、SQLite データベースに保存します。

CLI、ターミナル UI、Rust API、MCP サーバーから利用できます。データを取り込んだ後は、ネットワークに接続せずにローカルで検索できます。

API ドキュメント: [English](./docs/API.md) · [日本語](./docs/API_J.md)

## 主な機能

- 全件を収録した CVE アーカイブと、選択した補足データからデータベースを構築する
- CVE の差分更新と OSV の増分更新を適用する
- 識別子、テキスト、影響を受ける製品、CWE、CAPEC、CVSS、日付で CVE レコードを検索する。また、テキストで OSV アドバイザリを検索する
- 対応している OSV と CVE List のバージョン範囲に基づき、指定したパッケージのバージョンが脆弱性の影響を受けるか判定する
- ターミナル UI で CVE、OSV、CWE、CAPEC のデータを閲覧する
- GitHub の依存関係グラフから出力した SBOM と、SPDX または CycloneDX 形式の SBOM JSON を、ローカルの脆弱性データでスキャンする
- 検索、補足情報の取得、データベースの保守操作を MCP 経由で提供する

## 動作要件

利用には、次の環境が必要です。

- Rust 2024 Edition に対応する Rust ツールチェーン
- データソースをダウンロードするためのネットワーク接続
- CVE アーカイブの展開とデータベースの保存に必要な空き容量

既定では、カレントディレクトリにある `db.sqlite` をデータベースとして使用します。

```text
sqlite://./db.sqlite?mode=rwc
```

別の場所へ保存する場合は、`--db-url` オプションまたは `QANVULI_DB_URL` 環境変数を指定してください。

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

### データベースの初期化

最新のデータソースから新しいデータベースを構築するには、`init` を実行します。

```bash
qanvuli init
```

手元にある CVE アーカイブの使用や、ディスク使用量の抑制などには、次のオプションを指定します。

```bash
qanvuli init --zip ./data/all-cves.zip
qanvuli init --delete-existing
qanvuli init --eager-cleanup
qanvuli init --no-progress
```

通常、`init` は使用中のデータベースと同じディレクトリに、置き換え用の新しいデータベースを構築します。必須スキーマと所定の検索検証項目を確認し、データベース接続を閉じてから、使用中のデータベースを置き換えます。

置換前には WAL のチェックポイントを実行し、使用中のデータベースをロールバック用のバックアップへ移動します。データベース接続を安全に閉じられない場合は、置換を中止します。構築に失敗した場合も、使用中のデータベースは変更されません。

初期化中の競合を避けるため、SQLite を利用するほかのプロセスを停止してから実行してください。

`init --zip` で指定したアーカイブは、ユーザー所有のローカルファイルとして扱い、自動では削除しません。`--keep` が適用されるのは、`--zip` を省略したときに自動ダウンロードする CVE アーカイブだけです。

`--delete-existing`（`-D`）を指定すると、過去に置き換え用として作成した `*.qanvuli-new-*` と、使用中のデータベースを先に削除します。その後、必要なデータをダウンロードし、新しいデータベースを構築します。

このオプションを使うとピーク時のディスク使用量を抑えられますが、同時に進行している別の初期化を妨げるおそれがあります。また、削除後の処理に失敗すると、利用可能なデータベースは残りません。ほかに `qanvuli init` が実行されていないことを確認してから使用してください。

`--eager-cleanup`（`-C`）を指定すると、自動ダウンロードした CVE と OSV のアーカイブを、それぞれの取り込みが成功した時点で削除します。これにより、その後の初期化処理でピーク時のディスク使用量を抑えられます。CWE と CAPEC の自動ダウンロードファイルは、従来どおり取り込み直後に削除します。

`--zip` で指定したユーザー所有のアーカイブは削除しません。`--eager-cleanup` と `--keep` は同時に指定できません。

### OSV ソースの選択

`init` は、既定で GHSA と OSV（OSS-Fuzz）を取り込みます。`--osv-rustsec` や `--osv-pysec` などのフラグでソースを追加できます。`--osv-all` を指定すると、すべてのソースを選択します。利用できるフラグは `qanvuli init --help` で確認してください。

OSV ソースを選択できるのは `init` だけです。`update` と MCP の `update_db` は保存済みの選択内容だけを使用し、ソースを追加しません。選択内容が保存されていない場合は、OSV の同期をスキップします。

### データベースの更新

未適用の CVE 差分を取得・適用し、補足データを更新するには、`update` を実行します。

```bash
qanvuli update
qanvuli update --osv-refresh-all
qanvuli update --no-progress
```

ローカルの CVE アーカイブを取り込む場合は、次のように指定します。

```bash
qanvuli update --zip ./data/delta.zip
```

`--zip` を指定しない場合、`update` は CVE 差分を適用した後、CWE、CAPEC、KEV、EPSS を更新します。OSV は、保存済みの選択内容に基づいて更新します。

`--zip` を指定した場合は、指定した CVE アーカイブだけを取り込みます。

`update --zip` で指定したアーカイブもユーザー所有として扱い、処理の成否にかかわらず保持します。リモート更新では、`--keep` を指定すると、自動ダウンロードした CVE 差分アーカイブを保持します。`--keep` を省略した場合は、処理の成功後に削除することがあります。

リモートデータを対象とする `update` が失敗した場合は、`qanvuli update` を再実行すると、保存済みの状態から処理を再開できます。

更新処理は、すべてのデータソースを単一のアトミックなトランザクションで扱うわけではありません。後続の CWE、CAPEC、OSV、KEV、EPSS の更新に失敗しても、適用済みの CVE 差分とカーソルは保持されます。そのため、コマンドが失敗しても、データの一部は変更されている可能性があります。

`--osv-refresh-all` を指定すると OSV カーソルを無視し、選択したスナップショット内の全項目を挿入または更新（upsert）します。ただし、スナップショットに存在しない項目を削除済みとはみなしません。撤回されたアドバイザリも、撤回日時とともに引き続き参照できます。

### CVE アーカイブのダウンロード

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

`query package` は、対応している OSV のバージョン範囲を、エコシステム固有の規則に従って評価します。バージョンを評価できない場合や結果が曖昧な場合は、確認済みの検出結果には含めず、要確認として返します。

整形した JSON を出力するには、`--pretty` を指定します。

## データベースの保守

```bash
qanvuli db status
qanvuli db status --json
qanvuli db check
qanvuli db check --scan
qanvuli db check --full
qanvuli db rebuild-search
```

`db check` は、スキーマと所定の検索検証項目を確認します。`--scan` を指定すると、SQLite、外部キー、FTS、プロジェクションも検査します。`--full` では、最も処理負荷の高い整合性検査を実行します。

取り込んだ OSV の関連情報を使って、データソース間の識別子のリンクを再構築するには、次のコマンドを実行します。

```bash
qanvuli graph rebuild
```

データベースファイルは、元データから再生成できるものとして扱います。未対応のスキーマを直接修正する機能はないため、`qanvuli init` で再構築してください。

スキーマ 12 では、正規化したパッケージ識別子と PURL に索引を追加しています。スキーマ 11 の既存データベースも `qanvuli init` で再構築してください。

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

## CVSS 計算

CVSS v2.0、v3.0、v3.1、v4.0 のベクターを解析し、各メトリクスの意味を表示します。スコアと深刻度の計算にデータベースは必要ありません。

```bash
qanvuli cvss 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L'
```

## SBOM のスキャン

```bash
qanvuli sbom ./sbom.json
qanvuli sbom --file ./sbom.json --per-package-limit 5
qanvuli sbom ./sbom.json --sarif-output ./qanvuli.sarif
```

`sbom` は、GitHub の依存関係グラフから出力した SBOM と、SPDX または CycloneDX 形式の JSON を読み込みます。CycloneDX では、トップレベルの `components`、ルートの `metadata.component`、その配下に入れ子になったコンポーネントに対応しています。

PURL が付与されたパッケージを、OSV と CVE List のデータと照合します。バージョンの判定には、crates.io／Cargo、Go、GitHub Actions、Maven、npm、NuGet、PyPI、Pub、RubyGems に対応した規則を使います。

バージョンがない場合、バージョン方式に対応していない場合、判定が曖昧な場合は、要確認として返し、確認済みの検出結果には含めません。パッケージ名だけが一致する CVE は候補として扱い、確認済みの脆弱性件数には含めません。

スキャン結果は JSON 形式で標準出力に書き出します。`--sarif-output <PATH>` を指定すると、同じ結果を SARIF 2.1.0 ファイルにも出力します。このファイルは、脆弱性レポートやコードスキャンとの連携に利用できます。

SARIF の検出結果は、SBOM ファイル全体を参照します。現在は JSON 内の各コンポーネントの正確な行位置を保持していないため、検出箇所へ正確に移動する用途には適していません。

## MCP サーバー

```bash
qanvuli mcp
```

stdio サーバーとして、ローカルの CVE、CWE、CAPEC、OSV、KEV、EPSS に対するクエリと、データベースの更新機能を提供します。

### 検索と照会

パッケージ照会では、既定で詳細な照合根拠を省略します。一致の詳細を確認したい場合に限り、根拠情報を要求してください。

パッケージの一括照会と最近の更新一覧は、既定で簡潔な概要を返します。概要には、判定に必要な脆弱性や要確認の状態と、リスク情報が含まれます。`findings`、CWE、CVSS ベクター、影響を受けるバージョンの詳細が必要なパッケージまたは CVE に限り、`verbosity="full"` を指定してください。

OSV にデータがない場合でも、そのパッケージに CVE が存在する可能性があります。重要なパッケージやサポートが終了したパッケージについては、CVE List とベンダーのアドバイザリも確認してください。

`analyze_cvss_vector` ツールは、バージョン接頭辞を含む完全な CVSS v2.0、v3.0、v3.1、v4.0 ベクターを検証し、基本スコア、基本深刻度、各メトリクスの詳細を返します。この処理はデータベースへ問い合わせません。

### 接続と更新処理

MCP の検索では、既定で 4 本の独立した SQLite 読み取り接続を使用します。接続数は `QANVULI_MCP_READ_CONNECTIONS` に 1 から 8 までの値を指定して調整できます。

同時に実行できる更新は 1 件です。更新中に追加の更新を要求すると、実行中のジョブ ID を含むエラーを返します。ジョブ履歴は直近 64 件を保持します。

ファイルに保存したデータベースは、ダウンロード中も WAL を通じて読み取れます。読み取りでは確定済みの更新バッチを参照しますが、複数の読み取りが同じ時点の更新状態を参照する保証はありません。

HTTP 通信のタイムアウトは、接続に 15 秒、受信停止に 60 秒、全体に 1 時間を設定しています。同期ダウンロードでは、接続と全体のタイムアウトを適用します。

## ワークスペース

ワークスペースの主要ディレクトリは次のとおりです。

- `app/`: CLI とユーザー向けクレート
- `collector/`: データソースのクライアント
- `core/`: このリポジトリのワークスペースまたはソースチェックアウトから利用できる Rust API
- `db/`: スキーマ、インポート、クエリ
- `models/`: 各データソースのモデル
- `utils/`: アーカイブ、GitHub、ログ、日時に関するユーティリティ

Rust API は crates.io への公開を想定していません。このリポジトリのワークスペース、またはチェックアウトしたソースから path クレートとして利用してください。
