use std::fmt;

use serde::Deserialize;

macro_rules! text_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
        pub enum $name {
            $(
                #[serde(rename = $value)]
                $variant,
            )+
        }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value,)+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

text_enum!(Abstraction {
    Meta => "Meta",
    Standard => "Standard",
    Detailed => "Detailed",
});

text_enum!(Status {
    Stable => "Stable",
    Usable => "Usable",
    Draft => "Draft",
    Obsolete => "Obsolete",
    Deprecated => "Deprecated",
});

text_enum!(ViewType {
    Graph => "Graph",
    Explicit => "Explicit",
    Implicit => "Implicit",
});

text_enum!(RelationNature {
    ChildOf => "ChildOf",
    CanAlsoBe => "CanAlsoBe",
    CanFollow => "CanFollow",
    CanPrecede => "CanPrecede",
    PeerOf => "PeerOf",
});
