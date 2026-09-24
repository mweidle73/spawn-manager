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

package Spawn.Transport.Tests is

   type Testcase is new Ahven.Framework.Test_Case with null record;

   procedure Close_On_Exec_Flag;
   --  Verify control descriptors receive the close-on-exec flag.

   procedure Completion_Timeout;
   --  Verify the deadline starts with the first byte and bounds all others.

   procedure Extra_Data_Is_Rejected;
   --  Verify bytes queued beyond one frame are rejected.

   procedure First_Byte_Timeout;
   --  Verify a silent peer cannot block a bounded frame read.

   procedure Fragmented_Frame;
   --  Verify header and payload fragments are reassembled exactly.

   procedure Initialize (T : in out Testcase);
   --  Register transport tests.

   procedure Peer_Closure;
   --  Verify orderly closure is distinct from a timeout.

   procedure Ready_Data_Deadline;
   --  Verify queued data cannot make an expired completion deadline progress.

   procedure Send_And_Receive;
   --  Verify the exact-write path produces one complete frame.

   procedure Send_Large_Frame;
   --  Verify exact-write retries a frame larger than the socket send buffer.

end Spawn.Transport.Tests;
