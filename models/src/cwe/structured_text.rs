use serde::Deserialize;

use crate::cwe::enumeration::{LanguageName, StructuredCodeNature};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredText {
    #[serde(rename = "$value", default)]
    pub content: Vec<XhtmlNode>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredCode {
    #[serde(rename = "$value", default)]
    pub content: Vec<XhtmlNode>,
    #[serde(rename = "@Language")]
    pub language: Option<LanguageName>,
    #[serde(rename = "@Nature")]
    pub nature: StructuredCodeNature,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XhtmlNode {
    #[serde(rename = "$text")]
    Text(String),
    Br,
    Div(XhtmlElement),
    Span(XhtmlElement),
    A(XhtmlElement),
    B(XhtmlElement),
    I(XhtmlElement),
    Em(XhtmlElement),
    Strong(XhtmlElement),
    Sup(XhtmlElement),
    Img(XhtmlElement),
    Ol(XhtmlElement),
    Ul(XhtmlElement),
    Li(XhtmlElement),
    P(XhtmlElement),
    Code(XhtmlElement),
    Pre(XhtmlElement),
    Table(XhtmlElement),
    Thead(XhtmlElement),
    Tbody(XhtmlElement),
    Tr(XhtmlElement),
    Th(XhtmlElement),
    Td(XhtmlElement),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XhtmlElement {
    #[serde(rename = "@style")]
    pub style: Option<String>,
    #[serde(rename = "@class")]
    pub class: Option<String>,
    #[serde(rename = "@href")]
    pub href: Option<String>,
    #[serde(rename = "@src")]
    pub src: Option<String>,
    #[serde(rename = "@alt")]
    pub alt: Option<String>,
    #[serde(rename = "@title")]
    pub title: Option<String>,
    #[serde(rename = "@colspan")]
    pub colspan: Option<String>,
    #[serde(rename = "@rowspan")]
    pub rowspan: Option<String>,
    #[serde(rename = "$value", default)]
    pub content: Vec<XhtmlNode>,
}
