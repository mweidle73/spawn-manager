--
--  Process Spawn Manager
--
--  Copyright (C) 2026 secunet Security Networks AG
--
--  This program is free software; you can redistribute it and/or
--  modify it under the terms of the GNU General Public License
--  as published by the Free Software Foundation; either version 2
--  of the License, or (at your option) any later version.
--
--  This program is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
--  General Public License for more details.
--
--  As a special exception, if other files instantiate generics from this
--  unit, or you link this unit with other files to produce an executable,
--  this unit does not by itself cause the resulting executable to be covered
--  by the GNU General Public License. This exception does not invalidate any
--  other reason why the executable might be covered by the GNU Public
--  License.
--

with Ahven.Framework;

package Spawn.Protocol.Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Header_Bounds;
   --  Verify fixed and active complete-frame bounds.

   procedure Header_Golden_Data;
   --  Verify exact version 1 header bytes and decoding.

   procedure Header_Rejects_Invalid_Data;
   --  Verify malformed magic, version, kind and header length rejection.

   procedure Initialize (T : in out Testcase);
   --  Register protocol tests.

end Spawn.Protocol.Tests;
