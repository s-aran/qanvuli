use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct StructuredText {
    #[serde(rename = "$value", default)]
    pub content: Vec<XhtmlNode>,
}

impl StructuredText {
    pub fn plain_text(&self) -> String {
        let mut text = String::new();
        for node in &self.content {
            node.push_text(&mut text);
        }
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }
}

#[derive(Clone, Debug, Deserialize)]
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
    Sub(XhtmlElement),
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

impl XhtmlNode {
    fn push_text(&self, text: &mut String) {
        match self {
            Self::Text(value) => {
                text.push_str(value);
                text.push(' ');
            }
            Self::Br => text.push(' '),
            Self::Div(node)
            | Self::Span(node)
            | Self::A(node)
            | Self::B(node)
            | Self::I(node)
            | Self::Em(node)
            | Self::Strong(node)
            | Self::Sup(node)
            | Self::Sub(node)
            | Self::Img(node)
            | Self::Ol(node)
            | Self::Ul(node)
            | Self::Li(node)
            | Self::P(node)
            | Self::Code(node)
            | Self::Pre(node)
            | Self::Table(node)
            | Self::Thead(node)
            | Self::Tbody(node)
            | Self::Tr(node)
            | Self::Th(node)
            | Self::Td(node) => {
                for child in &node.content {
                    child.push_text(text);
                }
            }
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct XhtmlElement {
    #[serde(rename = "$value", default)]
    pub content: Vec<XhtmlNode>,
}
