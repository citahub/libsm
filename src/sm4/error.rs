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

use std::error;
use std::fmt::Display;
use std::fmt::Formatter;

pub type Sm4Result<T> = Result<T, Sm4Error>;

pub enum Sm4Error {
    ErrorBlockSize,
    ErrorDataLen,
    InvalidLastU8,
}

impl ::std::fmt::Debug for Sm4Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "{self}")
    }
}

impl From<Sm4Error> for &str {
    fn from(e: Sm4Error) -> Self {
        match e {
            Sm4Error::ErrorBlockSize => "the block size of SM4 must be 16",
            Sm4Error::ErrorDataLen => "the data len of SM4 must be 16",
            Sm4Error::InvalidLastU8 => {
                "the last u8 of cbc_decrypt out in SM4 must be positive which isn't greater than 16"
            }
        }
    }
}

impl error::Error for Sm4Error {}

impl Display for Sm4Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let err_msg = match self {
            Sm4Error::ErrorBlockSize => "the block size of SM4 must be 16",
            Sm4Error::ErrorDataLen => "the data len of SM4 must be 16",
            Sm4Error::InvalidLastU8 => {
                "the last u8 of cbc_decrypt out in SM4 must be positive which isn't greater than 16"
            }
        };
        write!(f, "{err_msg}")
    }
}

#[cfg(test)]
mod tests {
    use super::Sm4Error;

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", Sm4Error::ErrorBlockSize),
            "the block size of SM4 must be 16"
        )
    }
}
