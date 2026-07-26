# qanvuli 設計概要

![qanvuli logo](./logo.svg)

- Status: Draft
- Author: Sumiishi Aran
- Last updated: 2026-07-26

## 目的

qanvuliは公開されている脆弱性フィードをSQLiteへ取り込み、ローカル検索を提供する。
外部サービスのレート制限や可用性に依存せず、大量・反復検索を実行できることを目的とする。

対象データはCVE、CWE、CAPEC、OSV、CISA KEV、FIRST EPSSである。CLI、TUI、Rust API、MCPサーバーから同じデータベースを利用する。

## 責務

- 外部フィードとリリース資産の取得
- 入力形式の検証と正規化
- SQLiteデータベースの構築と差分更新
- FTSと識別子グラフの生成
- CVE、パッケージ、CWE、CAPEC、リスク情報の検索
- 置換、更新、検索構造の整合性確認

SaaSの運用、ベンダー固有の未公開情報の収集、OSVが対応しないバージョン方式の推測は責務に含めない。

## 構成

![high-level architecture](./diagram1.png)

- `collector`: CVE、CWE、CAPEC、OSV、KEV、EPSSの取得
- `models`: 外部形式のデシリアライズと検証
- `db`: スキーマ、インポート、検索、DB置換
- `core`: アプリケーション向け公開API
- `app`: CLI、TUI、MCP

## データ更新

初期化ではCVE Listの全件アーカイブと関連フィードから候補DBを構築する。候補DBのスキーマ、検索投影、インデックスを検証して接続を閉じた後、同一ファイルシステム上で既存DBと置き換える。
失敗時は既存DBを維持する。

更新ではCVE差分を公開日時順に適用し、CWE、CAPEC、OSV、KEV、EPSSを同期する。OSVの同期カーソルは、投入と検証が完了した時点で更新する。

大容量の二重ZIPは、サイズに応じてメモリまたは一時ファイルから読み込む。ディスク上のZIPは順次読み込み、メモリ上のZIPのみ並列展開する。

## 検索

検索値はSQLへ直接連結せず、バインド変数として渡す。FTSはCVEとOSVの自由文検索に使用し、構造化条件は正規化テーブルへ適用する。

パッケージ検索はOSVの明示バージョンと対応済み範囲形式を評価する。名前が一致しただけの候補を脆弱と判定しない。別名グラフでは同一性を表すaliasだけを推移的に解決し、upstreamとrelatedは別の関係として保持する。

DBの詳細は[データベース設計](../db/DESIGN.md)を参照する。
