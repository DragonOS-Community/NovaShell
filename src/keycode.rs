use num_enum::TryFromPrimitive;

#[repr(u8)]
#[derive(Debug, FromPrimitive, TryFromPrimitive, ToPrimitive, PartialEq, Eq, Clone)]
#[allow(dead_code)]
pub enum SpecialKeycode {
    LF = b'\n',
    CR = b'\r',
    BackSpace = b'\x7f',
    Tab = b'\t',

    ESC = 0x1B,
    PauseBreak = 0xE1,
}

impl Into<u8> for SpecialKeycode {
    fn into(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(dead_code)]
pub enum FunctionKeySuffix {
    Up,
    Down,
    Left,
    Right,

    Home,
    End,
    Delete,
}

impl FunctionKeySuffix {
    pub const SUFFIX_0: u8 = 0x5b;
    pub fn bytes(self) -> &'static [u8] {
        match self {
            FunctionKeySuffix::Up => &[0x5b, 0x41],
            FunctionKeySuffix::Down => &[0x5b, 0x42],
            FunctionKeySuffix::Left => &[0x5b, 0x44],
            FunctionKeySuffix::Right => &[0x5b, 0x43],
            FunctionKeySuffix::Home => &[0x5b, 0x48],
            FunctionKeySuffix::End => &[0x5b, 0x46],
            FunctionKeySuffix::Delete => &[0x5b, 0x33, 0x7e],
        }
    }

    pub fn try_from(value: &[u8]) -> Option<Self> {
        match value {
            [0x5b, 0x41] => Some(FunctionKeySuffix::Up),
            [0x5b, 0x42] => Some(FunctionKeySuffix::Down),
            [0x5b, 0x44] => Some(FunctionKeySuffix::Left),
            [0x5b, 0x43] => Some(FunctionKeySuffix::Right),
            [0x5b, 0x48] => Some(FunctionKeySuffix::Home),
            [0x5b, 0x46] => Some(FunctionKeySuffix::End),
            [0x5b, 0x33, 0x7e] => Some(FunctionKeySuffix::Delete),
            _ => None,
        }
    }

    pub fn should_read_more(value: &[u8]) -> bool {
        match value.len() {
            0 => true,
            1 => value[0] == Self::SUFFIX_0,
            2 => value[0] == Self::SUFFIX_0 && value[1] == 0x33,
            _ => false,
        }
    }
}

impl Into<&[u8]> for FunctionKeySuffix {
    fn into(self) -> &'static [u8] {
        self.bytes()
    }
}
