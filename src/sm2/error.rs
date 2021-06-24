// Copyright 2018 Cryptape Technology LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fmt::Display;
use std::fmt::Formatter;

pub enum Sm2Error {
    NotOnCurve,
    FieldSqrtError,
    InvalidDer,
    InvalidPublic,
    InvalidPrivate,
}

impl ::std::fmt::Debug for Sm2Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<Sm2Error> for &str {
    fn from(e: Sm2Error) -> Self {
        match e {
            Sm2Error::NotOnCurve => "the point not on curve",
            Sm2Error::FieldSqrtError => "field elem sqrt error",
            Sm2Error::InvalidDer => "invalid der",
            Sm2Error::InvalidPublic => "invalid public key",
            Sm2Error::InvalidPrivate => "invalid private key",
        }
    }
}

impl Display for Sm2Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let err_msg = match self {
            Sm2Error::NotOnCurve => "the point not on curve",
            Sm2Error::FieldSqrtError => "field elem sqrt error",
            Sm2Error::InvalidDer => "invalid der",
            Sm2Error::InvalidPublic => "invalid public key",
            Sm2Error::InvalidPrivate => "invalid private key",
        };
        write!(f, "{}", err_msg)
    }
}

#[cfg(test)]
mod tests {
    use super::Sm2Error;

    #[test]
    fn test_error_display() {
        let e = Sm2Error::InvalidPublic;
        assert_eq!(format!("{}", e), "invalid public key");
        assert_eq!(format!("{:?}", e), "invalid public key");
    }
}
