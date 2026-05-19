//! Gallery of `liana_ui::component::amount::amount_with_fiat` at every
//! [`AmountSize`], with and without a fiat value, plus the exact/tooltip
//! variants of `amount_with_fiat_tooltip`.

use liana::miniscript::bitcoin::Amount;
use liana_ui::{
    component::amount::{
        amount_with_fiat, amount_with_fiat_tooltip, AmountSize, Currency, FiatAmount,
    },
    icon,
    widget::*,
};

use crate::debug::{debug_chrome, debug_section, DebugMessage, DebugPageEntry};

pub static ENTRY: DebugPageEntry = DebugPageEntry { view };

static AMOUNT: Amount = Amount::from_sat(123_456_789);

fn sample_fiat(amount: Amount) -> FiatAmount {
    FiatAmount::new(amount.to_btc() * 95_000.0, Currency::USD).expect("non-negative")
}

fn view() -> Element<'static, DebugMessage> {
    let to_fiat = sample_fiat as fn(Amount) -> FiatAmount;
    let none = None::<fn(Amount) -> FiatAmount>;

    #[rustfmt::skip]
    let with_fiat = [
        (Container::new(amount_with_fiat(&AMOUNT, Some(to_fiat), AmountSize::L)), "amount_with_fiat(.., L)"),
        (Container::new(amount_with_fiat(&AMOUNT, Some(to_fiat), AmountSize::M)), "amount_with_fiat(.., M)"),
        (Container::new(amount_with_fiat(&AMOUNT, Some(to_fiat), AmountSize::S)), "amount_with_fiat(.., S)"),
    ];

    #[rustfmt::skip]
    let without_fiat = [
        (Container::new(amount_with_fiat(&AMOUNT, none, AmountSize::L)), "amount_with_fiat(.., None, L)"),
        (Container::new(amount_with_fiat(&AMOUNT, none, AmountSize::S)), "amount_with_fiat(.., None, S)"),
    ];

    let exact = amount_with_fiat_tooltip(
        &AMOUNT,
        Some(to_fiat),
        AmountSize::M,
        false,
        None::<Element<'static, DebugMessage>>,
    );
    let tooltip = amount_with_fiat_tooltip(
        &AMOUNT,
        Some(to_fiat),
        AmountSize::M,
        true,
        Some(icon::tooltip_icon().into()),
    );
    let extras = [
        (
            Container::new(exact),
            "amount_with_fiat_tooltip(.., approximate = false, no tooltip)",
        ),
        (
            Container::new(tooltip),
            "amount_with_fiat_tooltip(.., approximate = true, tooltip)",
        ),
    ];

    let body = Column::new()
        .spacing(40)
        .push(debug_section("amount_with_fiat", with_fiat))
        .push(debug_section("amount only", without_fiat))
        .push(debug_section("amount_with_fiat_tooltip", extras));

    debug_chrome("Amount + fiat", body)
}
