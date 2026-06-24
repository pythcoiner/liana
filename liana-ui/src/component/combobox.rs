use std::fmt::Display;

use iced::{
    widget::{
        combo_box::{self, ComboBox as IcedComboBox},
        container,
        text_input::{Icon, Side},
    },
    Font, Length, Padding, Pixels,
};

use crate::{theme, widget::*};

const FIELD_HEIGHT: f32 = 40.0;
const FIELD_PADDING: Padding = Padding {
    top: 9.6,
    right: 16.0,
    bottom: 9.6,
    left: 16.0,
};
const INPUT_SIZE: Pixels = Pixels(16.0);
const MENU_HEIGHT: f32 = 264.0;

const BOOTSTRAP_ICONS: Font = Font::with_name("bootstrap-icons");

pub type State<T> = combo_box::State<T>;
pub type Combobox<'a, Message> = Element<'a, Message>;

pub fn combobox<'a, T, Message>(
    state: &'a State<T>,
    placeholder: &'a str,
    selected: Option<&'a T>,
    on_selected: impl Fn(T) -> Message + 'static,
) -> Combobox<'a, Message>
where
    T: Display + Clone + 'static,
    Message: Clone + 'a,
{
    let input = IcedComboBox::new(state, placeholder, selected, on_selected)
        .width(Length::Fill)
        .padding(FIELD_PADDING)
        .size(INPUT_SIZE)
        .icon(chevron())
        .input_style(theme::combobox::input)
        .menu_style(theme::combobox::menu)
        .menu_height(Length::Fixed(MENU_HEIGHT));

    container(input)
        .width(Length::Fill)
        .height(Length::Fixed(FIELD_HEIGHT))
        .style(theme::combobox::field)
        .into()
}

fn chevron() -> Icon<Font> {
    Icon {
        font: BOOTSTRAP_ICONS,
        code_point: '\u{F282}',
        size: Some(Pixels(16.0)),
        spacing: 8.0,
        side: Side::Right,
    }
}

pub fn height() -> Length {
    Length::Fixed(FIELD_HEIGHT)
}
