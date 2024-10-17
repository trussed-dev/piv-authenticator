use crate::{reply::Reply, Authenticator, /*constants::PIV_AID,*/ Result};

use apdu_app::{App, CommandView, Data};
use iso7816::{Interface, Status};

#[cfg(feature = "apdu-dispatch")]
impl<T, const R: usize> App<R> for Authenticator<T>
where
    T: crate::Client,
{
    fn select(
        &mut self,
        interface: Interface,
        _apdu: CommandView<'_>,
        reply: &mut Data<R>,
    ) -> Result {
        if interface != Interface::Contact {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        self.select(Reply(reply))
    }

    fn deselect(&mut self) {
        self.deselect()
    }

    fn call(&mut self, interface: Interface, apdu: CommandView<'_>, reply: &mut Data<R>) -> Result {
        if interface != Interface::Contact {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        self.respond(apdu, &mut Reply(reply))
    }
}
