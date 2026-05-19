//! Placeholder for the signing-device modal gallery.
//!
//! The previous `liana_ui::component::modal::legacy::*` device-row constructors
//! were removed when device entries moved to `modal::device_entry` /
//! `DeviceStatus`. These two pages stay registered as placeholders until the
//! gallery is rebuilt against the new device-entry API.

use iced::Length;
use liana_ui::{
    component::{modal, text},
    theme,
    widget::*,
};

use crate::debug::{debug_chrome, DebugMessage, DebugPageEntry};

pub static ENTRY_PAGE_1: DebugPageEntry = DebugPageEntry { view: page_1 };
pub static ENTRY_PAGE_2: DebugPageEntry = DebugPageEntry { view: page_2 };

fn page_1() -> Element<'static, DebugMessage> {
    placeholder("Signing devices (1/2)")
}

fn page_2() -> Element<'static, DebugMessage> {
    placeholder("Signing devices (2/2)")
}

fn placeholder(title: &'static str) -> Element<'static, DebugMessage> {
    let note = Container::new(text::p1_regular(
        "modal::legacy::* device modals were removed; rebuild this gallery against modal::device_entry / DeviceStatus.",
    ))
    .width(Length::Fixed(modal::BTN_W as f32))
    .style(theme::card::border);
    debug_chrome(title, Column::new().push(note))
}
