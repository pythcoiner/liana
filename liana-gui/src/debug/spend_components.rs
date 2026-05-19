//! Gallery of the reusable spend-panel components in
//! `liana_ui::component::panels::spend`: coin rows (every status/label mix),
//! the coins-selection card, the fee-rate row and the recipient card.
//!
//! Messages route through `()` like every other debug-overlay interaction.

use std::sync::LazyLock;

use liana::miniscript::bitcoin::Amount;
use liana_ui::{
    component::{
        amount::{Currency, FiatAmount},
        form::Value,
        panels::spend::{
            coin_row, coin_selection, fee_rate_row, recipient_card, CoinLabel, CoinStatus,
            FeeLevel, SmartFee,
        },
    },
    widget::*,
};

use crate::debug::{debug_chrome, debug_section, DebugMessage, DebugPageEntry};

pub static ENTRY: DebugPageEntry = DebugPageEntry { view };

static AMOUNT: Amount = Amount::from_sat(931_877_204);
static FEE: Amount = Amount::from_sat(2_500);

static FEERATE: LazyLock<Value<String>> = LazyLock::new(|| Value {
    value: "12".to_string(),
    warning: None,
    valid: true,
});
static ADDRESS: LazyLock<Value<String>> = LazyLock::new(|| Value {
    value: "bc1qexampledebugaddress00000000000000000000".to_string(),
    warning: None,
    valid: true,
});
static DESCRIPTION: LazyLock<Value<String>> = LazyLock::new(|| Value {
    value: "Rent".to_string(),
    warning: None,
    valid: true,
});
static AMOUNT_FORM: LazyLock<Value<String>> = LazyLock::new(|| Value {
    value: "9.31877204".to_string(),
    warning: None,
    valid: true,
});

fn view() -> Element<'static, DebugMessage> {
    #[rustfmt::skip]
    let coins = [
        (Container::new(coin_row(CoinLabel::Outpoint("Cold storage top-up".into()), &AMOUNT, CoinStatus::Sequence(4_815), true, (), 1600.0)),
            "coin_row(Sequence, full pill, wide)"),
        (Container::new(coin_row(CoinLabel::Outpoint("Cold storage top-up".into()), &AMOUNT, CoinStatus::Sequence(4_815), true, (), 1400.0)),
            "coin_row(Sequence, compact pill, < 1500)"),
        (Container::new(coin_row(CoinLabel::Outpoint("A very long coin label that overflows".into()), &AMOUNT, CoinStatus::Sequence(4_815), true, (), 1200.0)),
            "coin_row(Sequence, compact pill + width-scaled label)"),
        (Container::new(coin_row(CoinLabel::Transaction("Exchange withdrawal".into()), &AMOUNT, CoinStatus::Sequence(2), false, (), 1600.0)),
            "coin_row(Transaction label, Sequence)"),
        (Container::new(coin_row(CoinLabel::None, &AMOUNT, CoinStatus::Unconfirmed, true, (), 1600.0)),
            "coin_row(no label, Unconfirmed, selected)"),
        (Container::new(coin_row(CoinLabel::Outpoint("Salary".into()), &AMOUNT, CoinStatus::Spent, false, (), 1600.0)),
            "coin_row(Outpoint label, Spent)"),
    ];

    fn sample_fiat(amount: Amount) -> FiatAmount {
        FiatAmount::new(amount.to_btc() * 95_000.0, Currency::USD).expect("non-negative")
    }
    let none = None::<fn(Amount) -> FiatAmount>;
    let fiat = || Some(sample_fiat as fn(Amount) -> FiatAmount);
    #[rustfmt::skip]
    let fees = [
        (Container::new(fee_rate_row(None, &FEERATE, |_| (), None, none, 1200.0, 1_000)),
            "fee_rate_row(disabled, no fee)"),
        (Container::new(fee_rate_row(None, &FEERATE, |_| (), Some(&FEE), none, 1200.0, 1_000)),
            "fee_rate_row(disabled, fee)"),
        (Container::new(fee_rate_row(None, &FEERATE, |_| (), Some(&FEE), fiat(), 1200.0, 1_000)),
            "fee_rate_row(disabled, fee + fiat)"),
        (Container::new(fee_rate_row(Some(SmartFee::Manual { on_smart: () }), &FEERATE, |_| (), Some(&FEE), fiat(), 1200.0, 1_000)),
            "fee_rate_row(enabled, Manual)"),
        (Container::new(fee_rate_row(Some(SmartFee::Smart { level: FeeLevel::Low, on_manual: (), on_low: (), on_medium: Some(()), on_high: () }), &FEERATE, |_| (), Some(&FEE), fiat(), 1200.0, 1_000)),
            "fee_rate_row(enabled, Smart: Low, wide)"),
        (Container::new(fee_rate_row(Some(SmartFee::Smart { level: FeeLevel::Medium, on_manual: (), on_low: (), on_medium: Some(()), on_high: () }), &FEERATE, |_| (), Some(&FEE), fiat(), 1200.0, 1_000)),
            "fee_rate_row(enabled, Smart: Medium, wide)"),
        (Container::new(fee_rate_row(Some(SmartFee::Smart { level: FeeLevel::High, on_manual: (), on_low: (), on_medium: Some(()), on_high: () }), &FEERATE, |_| (), Some(&FEE), fiat(), 1200.0, 1_000)),
            "fee_rate_row(enabled, Smart: High, wide)"),
        (Container::new(fee_rate_row(Some(SmartFee::Smart { level: FeeLevel::Low, on_manual: (), on_low: (), on_medium: None, on_high: () }), &FEERATE, |_| (), Some(&FEE), fiat(), 1200.0, 1_000)),
            "fee_rate_row(enabled, Smart: Low, no medium)"),
        (Container::new(fee_rate_row(Some(SmartFee::Smart { level: FeeLevel::Medium, on_manual: (), on_low: (), on_medium: Some(()), on_high: () }), &FEERATE, |_| (), Some(&FEE), fiat(), 700.0, 1_000)),
            "fee_rate_row(enabled, Smart, narrow split)"),
    ];

    let selection = [(
        Container::new(coin_selection(vec![
            coin_row(
                CoinLabel::Outpoint("Cold storage top-up".into()),
                &AMOUNT,
                CoinStatus::Sequence(144),
                true,
                (),
                1600.0,
            ),
            coin_row(
                CoinLabel::None,
                &AMOUNT,
                CoinStatus::Unconfirmed,
                false,
                (),
                1600.0,
            ),
        ])),
        "coin_selection(rows)",
    )];

    #[rustfmt::skip]
    let recipients = [
        (Container::new(recipient_card(&ADDRESS, &DESCRIPTION, &AMOUNT_FORM, None, false, None, None, |_| (), |_| (), |_| (), None, Some(()))),
            "recipient_card(Some(delete), ..)"),
        (Container::new(recipient_card(&ADDRESS, &DESCRIPTION, &AMOUNT_FORM, None, false, None, None, |_| (), |_| (), |_| (), None, None)),
            "recipient_card(None, ..) — recovery"),
    ];

    let body = Column::new()
        .spacing(40)
        .push(debug_section("coin_row", coins))
        .push(debug_section("fee_rate_row", fees))
        .push(debug_section("coin_selection", selection))
        .push(debug_section("recipient_card", recipients));

    debug_chrome("Spend components", body)
}
