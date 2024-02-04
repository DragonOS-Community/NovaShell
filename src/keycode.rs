use num_enum::TryFromPrimitive;

#[repr(u8)]
#[derive(Debug, FromPrimitive, TryFromPrimitive, ToPrimitive, PartialEq, Eq, Clone)]
#[allow(dead_code)]
pub enum SpecialKeycode {
    LF = b'\n',
    CR = b'\r',
    Delete = b'\x7f',
    BackSpace = b'\x08',
    Tab = b'\t',

    FunctionKeyPrefix = 0xE0,
    PauseBreak = 0xE1,
}

#[repr(u8)]
#[derive(Debug, FromPrimitive, TryFromPrimitive, ToPrimitive, PartialEq, Eq, Clone)]
#[allow(dead_code)]
pub enum FunctionKeySuffix {
    Up = 0x48,
    Down = 0x50,
    Left = 0x4B,
    Right = 0x4D,

    Home = 0x47,
    End = 0x4F,
}

impl Into<u8> for SpecialKeycode {
    fn into(self) -> u8 {
        self as u8
    }
}
