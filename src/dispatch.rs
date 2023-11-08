use crate::{reply::Reply, Authenticator, /*constants::PIV_AID,*/ Result};

use apdu_dispatch::{app::App, command, response, Command};
use iso7816::{Interface, Status};

#[cfg(feature = "apdu-dispatch")]
impl<T> App<{ command::SIZE }, { response::SIZE }> for Authenticator<T>
where
    T: crate::Client,
{
    fn select(
        &mut self,
        interface: Interface,
        _apdu: &Command,
        reply: &mut response::Data,
    ) -> Result {
        if interface != Interface::Contact {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        self.select(Reply(reply))
    }

    fn deselect(&mut self) {
        self.deselect()
    }

    fn call(&mut self, interface: Interface, apdu: &Command, reply: &mut response::Data) -> Result {
        if interface != Interface::Contact {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        self.respond(apdu, &mut Reply(reply))
    }
}
