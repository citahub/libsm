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

pub type Sm3Result<T> = Result<T, Sm3Error>;

pub enum Sm3Error {
    ErrorMsgLen,
}

impl std::fmt::Debug for Sm3Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<Sm3Error> for &str {
    fn from(e: Sm3Error) -> Self {
        match e {
            Sm3Error::ErrorMsgLen => "SM3 Pad: error msgLen",
        }
    }
}

impl Display for Sm3Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let err_msg = match self {
            Sm3Error::ErrorMsgLen => "SM3 Pad: error msgLen",
        };
        write!(f, "{}", err_msg)
    }
}

#[cfg(test)]
mod tests {
    use super::Sm3Error;

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", Sm3Error::ErrorMsgLen),
            "SM3 Pad: error msgLen"
        )
    }
}
