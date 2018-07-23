// Copyright (C) 2018
//
// This file is part of libsm.
//
// libsm is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// libsm is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with libsm.  If not, see <http://www.gnu.org/licenses/>.

pub mod cipher;
pub mod cipher_mode;

pub type Mode = self::cipher_mode::CipherMode;
pub type Cipher = self::cipher_mode::SM4CipherMode;