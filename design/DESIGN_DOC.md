# Design Doc

Qanvuli

![img](./logo.svg)


* Status: Draft
* Author: Sumiishi Aran
* Last Updated: 2026-04-19


## 概要

"Qanvuli" はCVE.orgから発行されるCVE情報をローカルデータベースに保存して，検索を高速で検索することを実現するソフトウェアコンポーネントである。

本ソフトウェアの責務は，CVEデータの取得，正規化，ローカルデータベースへの反映，検索APIの提供である。

本ソフトウェアはアプリケーションやWebサービスとして提供されるものではない。ソフトウェアコンポーネントであり，ライブラリーとして他のアプリケーションに組込まれて使用されることを想定している。

### 背景

CVE.orgや関連サイトでは検索が行なえるが，
* 検索機能が限定的である
* レート制限や利用規約の影響を受ける
* 大量の検索や定期的な検索用途には向かない
* 外部サービスの可用性に依存する

一方でCVEのJSONデータはGitHubで公開されており，ローカルにDBを構築することで公式や関連サイトを参照することなく脆弱性情報が得られる。


## やること

1. 公式CVEをローカルデータベースに同期すること
1. データベースの一括挿入と差分挿入の両方を扱えること
1. GitHubからCVEのJSONファイルを取得してローカルDBを構築する
1. ソフトウェアコンポーネント(e.g., ライブラリー、クレート)として提供する

## やらないこと

1. SaaSとして一般提供する
1. SBOMや同等のソフトウェア部品表ないし構成表やそれに準ずるデータの読み取り
1. CVE以外の脆弱性情報の取り込み


## 詳細設計

### 高レベルアーキテクチャー


![img](./diagram1.png)

#### 構成要素

1. CVEのJSONファイルをGitHubから取得する
1. SQLiteのデータベースに書き込む
1. 指定されたクエリーに従ってSQLiteのデータベースを検索する



### CVEのJSONファイルをGitHubから取得する

CVE.orgが提供する脆弱性情報はGitHubの該当リポジトリのリリースページからダウンロードする機能を開発する。
CVE公式のJSONファイルが格納されているリポジトリは以下のとおりである。
https://github.com/CVEProject/cvelistV5

このリポジトリは1時間毎に更新される。更新内容は以下の通りである:
* 全期間の脆弱性データ: `*_all_CVEs_at_midnight.zip.zip`
* 前回との差分: `*_delta_CVEs_at_*.zip`

使い分けは以下の通りとする:
* 全期間の脆弱性データ
    * 初回
    * ローカルデータベースの最終更新日時が24時間経過
* 前回との差分
    * ローカルデータベースの最終更新日時が24時間未満

この使い分けが存在するため，データベース格納には2つのモードを設ける
* 

### SQLiteのデータベースに書き込む

データベースは別資料に記載のテーブル構成とする。



### 指定されたクエリーに従ってSQLiteのデータベースを検索する

ORMライクな検索クエリーとする。
例えば以下のような呼び出し方法である。

```rust
// 1件を引き当てる
let id_q = qanvuli::model::query::id::new("CVE-YYYY-NNNNN");
let cve = id_q.as_cve();

// 期間で抽出する
let published_q = qanvuli::model::query::published::new();
let published_start_q = published_q.gte("2020-01-01");
let published_end_q = published_q.lt("2021-01-01");
let cve_list = qanvuli::model::query::filter(published_start_q).filter(published_end_q).as_list();

// CVSSで抽出する+降順ソート
let cvss_q = qanvuli::model::query::cvss_v4();
let cve_list = qanvuli::model::query::filter(cvss_q).order_by(cvss_q.desc()).as_list();
```


