use iced::widget::container::Style;
use iced::{Background, Border};

use crate::{
    component::text::{self, Text},
    icon, image, theme,
    theme::palette::TileTone,
    widget::*,
};

const BADGE_SIZE: u32 = 40;
pub const AVATAR_SIZE: u32 = 30;
const AVATAR_TEXT_SIZE: u32 = 12;
const ICON_SIZE: u32 = BADGE_SIZE / 2;
const LIANA_ICON_SIZE: u32 = 25;
const TILE_SIZE: u32 = 44;
const TILE_RADIUS: f32 = 12.0;
const TILE_ICON_SIZE: u32 = 20;
const TILE_L_SIZE: u32 = 48;
const TILE_L_RADIUS: f32 = 14.0;
const TILE_L_ICON_SIZE: u32 = 24;
const TILE_XL_SIZE: u32 = 56;
const TILE_XL_RADIUS: f32 = 16.0;
const TILE_XL_ICON_SIZE: u32 = 26;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TileName {
    Org,
    Wallet,
    Setting,
    About,
    KeyInternal,
    KeyExternal,
    KeyService,
    Device,
    Account,
    DeviceMuted,
    Registering,
    RegFailed,
    Restricted,
    Import,
    Paste,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum TileToneName {
    Accent,
    Neutral,
    Muted,
    Danger,
}

#[derive(Debug, Copy, Clone, PartialEq)]
struct TileSize {
    size: u32,
    radius: f32,
    icon_size: u32,
}

impl TileSize {
    const DEFAULT: Self = Self {
        size: TILE_SIZE,
        radius: TILE_RADIUS,
        icon_size: TILE_ICON_SIZE,
    };

    const L: Self = Self {
        size: TILE_L_SIZE,
        radius: TILE_L_RADIUS,
        icon_size: TILE_L_ICON_SIZE,
    };

    const XL: Self = Self {
        size: TILE_XL_SIZE,
        radius: TILE_XL_RADIUS,
        icon_size: TILE_XL_ICON_SIZE,
    };
}

struct TileSpec<'a> {
    icon: crate::widget::Text<'a>,
    tone: TileToneName,
    size: TileSize,
}

pub fn badge_with_style<T, S>(icon: crate::widget::Text<'static>, style: S) -> Container<'static, T>
where
    S: Fn(&theme::Theme) -> Style + 'static,
{
    Container::new(icon.width(ICON_SIZE))
        .style(style)
        .center_x(BADGE_SIZE)
        .center_y(BADGE_SIZE)
}

macro_rules! icon_badge {
    ($name:ident, $icon:ident, $style:ident) => {
        pub fn $name<T>() -> Container<'static, T> {
            badge_with_style(icon::$icon(), theme::badge::$style)
        }
    };
}

icon_badge!(receive, receive_icon, simple);
icon_badge!(cycle, arrow_repeat, simple);
icon_badge!(spend, send_icon, simple);
icon_badge!(success, check_icon, success);
icon_badge!(tooltip, tooltip_icon, simple);
icon_badge!(network, network_icon, simple);
icon_badge!(block, block_icon, simple);
icon_badge!(bitcoin, bitcoin_icon, simple);
icon_badge!(setting, wrench_icon, simple);
icon_badge!(wallet, wallet_icon, simple);
icon_badge!(backup, backup_icon, simple);
icon_badge!(restore, restore_icon, simple);

pub fn tile<'a, M>(name: TileName) -> Container<'a, M> {
    let spec = tile_spec(name);
    let tone = spec.tone;
    let size = spec.size;
    let icon =
        spec.icon
            .width(size.size)
            .size(size.icon_size)
            .style(move |theme: &theme::Theme| iced::widget::text::Style {
                color: Some(tile_tone(theme, tone).fg),
            });

    Container::new(icon)
        .style(move |theme| tile_style(theme, tone, size.radius))
        .center_x(size.size)
        .center_y(size.size)
}

pub fn avatar<'a, M: 'a>(initials: String) -> Container<'a, M> {
    Container::new(
        text::new::small_caption(initials)
            .size(AVATAR_TEXT_SIZE)
            .bold(),
    )
    .center_x(AVATAR_SIZE)
    .center_y(AVATAR_SIZE)
    .style(theme::badge::avatar)
}

pub fn coin<T>() -> Container<'static, T> {
    Container::new(
        image::liana_grey_logo()
            .height(LIANA_ICON_SIZE)
            .width(LIANA_ICON_SIZE),
    )
    .style(theme::badge::simple)
    .center_x(BADGE_SIZE)
    .center_y(BADGE_SIZE)
}

fn tile_spec<'a>(name: TileName) -> TileSpec<'a> {
    match name {
        TileName::Org => TileSpec {
            icon: icon::org_icon(),
            tone: TileToneName::Accent,
            size: TileSize::DEFAULT,
        },
        TileName::Wallet => TileSpec {
            icon: icon::wallet_icon(),
            tone: TileToneName::Accent,
            size: TileSize::DEFAULT,
        },
        TileName::Setting => TileSpec {
            icon: icon::wrench_icon(),
            tone: TileToneName::Accent,
            size: TileSize::DEFAULT,
        },
        TileName::About => TileSpec {
            icon: icon::tooltip_icon(),
            tone: TileToneName::Accent,
            size: TileSize::DEFAULT,
        },
        TileName::KeyInternal => TileSpec {
            icon: icon::round_key_icon(),
            tone: TileToneName::Neutral,
            size: TileSize::DEFAULT,
        },
        TileName::KeyExternal => TileSpec {
            icon: icon::scale_icon(),
            tone: TileToneName::Neutral,
            size: TileSize::DEFAULT,
        },
        TileName::KeyService => TileSpec {
            icon: icon::shield_icon(),
            tone: TileToneName::Neutral,
            size: TileSize::DEFAULT,
        },
        TileName::Device => TileSpec {
            icon: icon::usb_icon(),
            tone: TileToneName::Neutral,
            size: TileSize::DEFAULT,
        },
        TileName::Account => TileSpec {
            icon: icon::person_icon(),
            tone: TileToneName::Neutral,
            size: TileSize::DEFAULT,
        },
        TileName::DeviceMuted => TileSpec {
            icon: icon::usb_icon(),
            tone: TileToneName::Muted,
            size: TileSize::DEFAULT,
        },
        TileName::Registering => TileSpec {
            icon: icon::usb_icon(),
            tone: TileToneName::Accent,
            size: TileSize::L,
        },
        TileName::RegFailed => TileSpec {
            icon: icon::warning_icon(),
            tone: TileToneName::Danger,
            size: TileSize::L,
        },
        TileName::Restricted => TileSpec {
            icon: icon::lock_icon(),
            tone: TileToneName::Muted,
            size: TileSize::XL,
        },
        TileName::Import => TileSpec {
            icon: icon::import_icon(),
            tone: TileToneName::Neutral,
            size: TileSize::DEFAULT,
        },
        TileName::Paste => TileSpec {
            icon: icon::paste_icon(),
            tone: TileToneName::Neutral,
            size: TileSize::DEFAULT,
        },
    }
}

fn tile_tone(theme: &theme::Theme, tone: TileToneName) -> TileTone {
    match tone {
        TileToneName::Accent => theme.colors.tile_tones.accent,
        TileToneName::Neutral => theme.colors.tile_tones.neutral,
        TileToneName::Muted => theme.colors.tile_tones.muted,
        TileToneName::Danger => theme.colors.tile_tones.danger,
    }
}

fn tile_style(theme: &theme::Theme, tone: TileToneName, radius: f32) -> Style {
    let tone = tile_tone(theme, tone);

    Style {
        background: Some(Background::Color(
            tone.bg.unwrap_or(theme.colors.tile_tones.background),
        )),
        text_color: Some(tone.fg),
        border: Border {
            radius: radius.into(),
            width: 0.0,
            color: iced::Color::TRANSPARENT,
            ..Default::default()
        },
        ..Default::default()
    }
}
