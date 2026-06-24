use std::fmt::Display;

use iced::{
    mouse,
    widget::{
        button, column,
        combo_box::{self, ComboBox as IcedComboBox},
        container, mouse_area, row, scrollable,
        text_input::Icon as IcedIcon,
        Space,
    },
    Alignment, Border, Font, Length, Padding, Pixels, Shadow, Vector,
};

use crate::{
    color,
    component::{
        badge,
        text::{self, Text},
    },
    icon, theme,
    widget::*,
};

const FIELD_HEIGHT: f32 = 40.0;
const FIELD_PADDING: Padding = Padding {
    top: 9.6,
    right: 16.0,
    bottom: 9.6,
    left: 16.0,
};
const INPUT_SIZE: Pixels = Pixels(16.0);
const MENU_HEIGHT: f32 = 264.0;
const MENU_ROW_PADDING: Padding = Padding {
    top: 9.0,
    right: 14.0,
    bottom: 9.0,
    left: 14.0,
};
const MENU_HEADER_PADDING: Padding = Padding {
    top: 9.0,
    right: 14.0,
    bottom: 5.0,
    left: 14.0,
};
const MENU_SHADOW: Shadow = Shadow {
    color: color::BLACK_15,
    offset: Vector { x: 0.0, y: 4.0 },
    blur_radius: 10.0,
};

const BOOTSTRAP_ICONS: Font = Font::with_name("bootstrap-icons");

#[derive(Debug, Clone)]
pub struct State<T: Display + Clone> {
    combo_box: combo_box::State<T>,
    is_open: bool,
}

impl<T: Display + Clone> State<T> {
    pub fn new(options: Vec<T>) -> Self {
        Self {
            combo_box: combo_box::State::new(options),
            ..Self::default()
        }
    }

    pub fn with_selection(options: Vec<T>, selection: Option<&T>) -> Self {
        Self {
            combo_box: combo_box::State::with_selection(options, selection),
            ..Self::default()
        }
    }

    pub fn open(&mut self) {
        self.is_open = true;
    }

    pub fn close(&mut self) {
        self.is_open = false;
    }

    pub fn is_open(&self) -> bool {
        self.is_open
    }

    fn combo_box(&self) -> &combo_box::State<T> {
        &self.combo_box
    }
}

impl<T: Display + Clone> Default for State<T> {
    fn default() -> Self {
        Self {
            combo_box: combo_box::State::new(Vec::new()),
            is_open: false,
        }
    }
}

pub type Combobox<'a, Message> = Element<'a, Message>;

pub enum MenuEntry<'a, T: Display + Clone, Message> {
    Header(Element<'a, Message>),
    Option {
        value: T,
        body: Element<'a, Message>,
        selected: bool,
    },
    Empty(Element<'a, Message>),
}

pub struct EditableMenuActions<F, Message> {
    pub on_input: Option<F>,
    pub on_open: Option<Message>,
    pub on_close: Option<Message>,
}

/// Trailing state of an [`email_entry`]: an optional "already a signer" note and the
/// selection check, which can appear together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    None,
    Selected,
    AlreadySigner,
    AlreadySignerSelected,
}

/// A member row: an initials avatar, the name over the email, and a trailing [`Tag`]. When
/// `email` is empty the row is a single line (used for emails with no member name).
pub fn email_entry<'a, M: 'a>(avatar: &str, name: &str, email: &str, tag: Tag) -> Element<'a, M> {
    let details = column![text::new::b5_medium(name.to_string())]
        .push_maybe(
            (!email.is_empty())
                .then(|| text::new::small_caption(email.to_string()).style(theme::text::secondary)),
        )
        .spacing(2)
        .width(Length::Fill);
    row![badge::avatar(avatar.to_string()), details, trailing(tag)]
        .spacing(11)
        .align_y(Alignment::Center)
        .into()
}

fn trailing<'a, M: 'a>(tag: Tag) -> Element<'a, M> {
    let note = || text::new::small_caption("already a signer").style(theme::text::muted);
    let check = || icon::check_icon().size(13).style(theme::text::success);
    match tag {
        Tag::None => Space::with_width(Length::Shrink).into(),
        Tag::Selected => check().into(),
        Tag::AlreadySigner => note().into(),
        Tag::AlreadySignerSelected => row![note(), check()]
            .spacing(6)
            .align_y(Alignment::Center)
            .into(),
    }
}

pub fn combobox<'a, T, Message>(
    state: &'a State<T>,
    placeholder: &'a str,
    selected: Option<T>,
    on_selected: impl Fn(T) -> Message + 'static,
) -> Combobox<'a, Message>
where
    T: Display + Clone + 'static,
    Message: Clone + 'a + 'static,
{
    wrap_combobox(styled_combobox(state, placeholder, selected, on_selected))
}

pub fn editable_combobox<'a, T, Message>(
    state: &'a State<T>,
    placeholder: &'a str,
    selected: Option<T>,
    on_selected: impl Fn(T) -> Message + 'static,
    on_input: impl Fn(String) -> Message + 'static,
    on_close: Message,
) -> Combobox<'a, Message>
where
    T: Display + Clone + 'static,
    Message: Clone + 'a + 'static,
{
    wrap_combobox(
        styled_combobox(state, placeholder, selected, on_selected)
            .on_input(on_input)
            .on_close(on_close),
    )
}

fn styled_combobox<'a, T, Message>(
    state: &'a State<T>,
    placeholder: &'a str,
    selected: Option<T>,
    on_selected: impl Fn(T) -> Message + 'static,
) -> IcedComboBox<'a, T, Message, theme::Theme, Renderer>
where
    T: Display + Clone + 'static,
    Message: Clone + 'a,
{
    IcedComboBox::new(
        state.combo_box(),
        placeholder,
        selected.as_ref(),
        on_selected,
    )
    .width(Length::Fill)
    .padding(FIELD_PADDING)
    .size(INPUT_SIZE)
    .icon(iced_chevron())
    .input_style(theme::combobox::input)
    .menu_style(theme::combobox::menu)
    .menu_height(Length::Fixed(MENU_HEIGHT))
}

pub fn editable_menu_combobox<'a, T, Message, F>(
    state: &'a State<T>,
    placeholder: &'a str,
    value: String,
    on_selected: impl Fn(T) -> Message + 'static,
    entries: Vec<MenuEntry<'a, T, Message>>,
    actions: EditableMenuActions<F, Message>,
) -> Combobox<'a, Message>
where
    T: Display + Clone + 'static,
    Message: Clone + 'a + 'static,
    F: Fn(String) -> Message + 'static,
{
    let input = input(
        placeholder,
        value,
        actions.on_input,
        actions.on_close.clone(),
        actions.on_open.clone(),
    );
    let menu: Option<Element<'a, Message>> = state
        .is_open()
        .then(|| menu(entries, on_selected))
        .map(|menu| container(menu).padding(Padding::from([4.0, 0.0])).into());

    if let Some(menu) = menu {
        column![input, menu]
    } else {
        column![input]
    }
    .spacing(0)
    .into()
}

fn input<'a, Message, F>(
    placeholder: &'a str,
    value: String,
    on_input: Option<F>,
    on_close: Option<Message>,
    on_open: Option<Message>,
) -> Element<'a, Message>
where
    Message: Clone + 'a,
    F: Fn(String) -> Message + 'static,
{
    let mut field = crate::widget::text_input::TextInput::new(placeholder, value)
        .width(Length::Fill)
        .padding(FIELD_PADDING)
        .size(INPUT_SIZE.0)
        .icon(text_input_chevron())
        .style(theme::text_input::form);

    if let Some(on_input) = on_input {
        field = field.on_input(on_input);
    }

    if let Some(on_close) = on_close.clone() {
        field = field.on_blur(on_close);
    }

    let field: Element<'a, Message> = wrap_field(field.into());
    if let Some(on_open) = on_open {
        mouse_area(field)
            .on_press(on_open)
            .interaction(mouse::Interaction::Text)
            .into()
    } else {
        field
    }
}

fn menu<'a, T, Message>(
    entries: Vec<MenuEntry<'a, T, Message>>,
    on_selected: impl Fn(T) -> Message + 'static,
) -> Element<'a, Message>
where
    T: Display + Clone + 'static,
    Message: Clone + 'a,
{
    let body = entries
        .into_iter()
        .fold(column![].spacing(0), |column, entry| match entry {
            MenuEntry::Header(content) => {
                column.push(container(content).padding(MENU_HEADER_PADDING))
            }
            MenuEntry::Option {
                value,
                body,
                selected,
            } => column.push(menu_option(body, selected, on_selected(value))),
            MenuEntry::Empty(content) => column.push(container(content).padding(MENU_ROW_PADDING)),
        });

    container(scrollable(body))
        .max_height(MENU_HEIGHT)
        .width(Length::Fill)
        .style(menu_panel)
        .into()
}

fn menu_option<'a, Message>(
    content: Element<'a, Message>,
    selected: bool,
    on_press: Message,
) -> Element<'a, Message>
where
    Message: Clone + 'a,
{
    Button::new(content)
        .width(Length::Fill)
        .padding(MENU_ROW_PADDING)
        .style(move |theme, status| menu_option_style(theme, status, selected))
        .on_press(on_press)
        .into()
}

fn menu_option_style(
    theme: &theme::Theme,
    status: button::Status,
    selected: bool,
) -> button::Style {
    let menu = theme.colors.menus.pick_list;
    let hovered = matches!(status, button::Status::Hovered | button::Status::Pressed);
    button::Style {
        background: Some(
            if selected || hovered {
                theme.colors.combobox.selected
            } else {
                menu.background
            }
            .into(),
        ),
        text_color: menu.text,
        ..button::Style::default()
    }
}

fn menu_panel(theme: &theme::Theme) -> container::Style {
    let menu = theme.colors.menus.pick_list;
    container::Style {
        background: Some(menu.background.into()),
        border: Border {
            color: menu.border,
            width: 1.0,
            radius: 4.0.into(),
            ..Default::default()
        },
        shadow: MENU_SHADOW,
        ..container::Style::default()
    }
}

fn wrap_combobox<'a, T, Message>(
    input: IcedComboBox<'a, T, Message, theme::Theme, Renderer>,
) -> Combobox<'a, Message>
where
    T: Display + Clone + 'static,
    Message: Clone + 'a,
{
    container(input)
        .width(Length::Fill)
        .height(Length::Fixed(FIELD_HEIGHT))
        .style(theme::combobox::field)
        .into()
}

fn wrap_field<'a, Message>(input: Element<'a, Message>) -> Combobox<'a, Message>
where
    Message: Clone + 'a,
{
    container(input)
        .width(Length::Fill)
        .height(Length::Fixed(FIELD_HEIGHT))
        .style(container::transparent)
        .into()
}

fn iced_chevron() -> IcedIcon<Font> {
    IcedIcon {
        font: BOOTSTRAP_ICONS,
        code_point: '\u{F282}',
        size: Some(Pixels(16.0)),
        spacing: 8.0,
        side: iced::widget::text_input::Side::Right,
    }
}

fn text_input_chevron() -> crate::widget::text_input::Icon<Font> {
    crate::widget::text_input::Icon {
        font: BOOTSTRAP_ICONS,
        code_point: '\u{F282}',
        size: Some(Pixels(16.0)),
        spacing: 8.0,
        side: crate::widget::text_input::Side::Right,
    }
}

pub fn menu_header<'a, Message>(label: impl Display) -> Element<'a, Message> {
    text::new::small_caption(label.to_string().to_uppercase())
        .style(theme::text::border)
        .bold()
        .into()
}

pub fn height() -> Length {
    Length::Fixed(FIELD_HEIGHT)
}
