// Copyright (C) 2022 Nicolas Stalder AND  Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

use crate::{reply::Reply, Authenticator, /*constants::PIV_AID,*/ Result};

use apdu_dispatch::{app::App, command, response, Command};
use trussed::client;

#[cfg(feature = "apdu-dispatch")]
impl<T> App<{ command::SIZE }, { response::SIZE }> for Authenticator<T>
where
    T: client::Client + client::Ed255 + client::Tdes,
{
    fn select(&mut self, _apdu: &Command, reply: &mut response::Data) -> Result {
        self.select(Reply(reply))
    }

    fn deselect(&mut self) {
        self.deselect()
    }

    fn call(
        &mut self,
        _: iso7816::Interface,
        apdu: &Command,
        reply: &mut response::Data,
    ) -> Result {
        self.respond(apdu, &mut Reply(reply))
    }
}
