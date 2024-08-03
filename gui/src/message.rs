use crate::{app, hw::HardwareWalletMessage, installer, launcher, loader};

#[derive(Debug)]
pub enum Key {
    Tab(bool),
}

#[derive(Debug)]
pub enum Message {
    CtrlC,
    FontLoaded(Result<(), iced::font::Error>),
    Launch(Box<launcher::Message>),
    Install(Box<installer::Message>),
    Load(Box<loader::Message>),
    Run(Box<app::Message>),
    KeyPressed(Key),
    Event(iced::Event),
    HardwareWallet(HardwareWalletMessage),
}

impl From<HardwareWalletMessage> for Message {
    fn from(value: HardwareWalletMessage) -> Self {
        Self::HardwareWallet(value)
    }
}

impl From<Result<(), iced::font::Error>> for Message {
    fn from(value: Result<(), iced::font::Error>) -> Self {
        Self::FontLoaded(value)
    }
}
