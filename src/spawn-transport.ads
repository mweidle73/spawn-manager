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

with Ada.Streams;
with Interfaces.C;

package Spawn.Transport is

   Frame_Completion_Timeout_MS : constant Positive := 5_000;

   function Receive_Frame
     (Descriptor            : Interfaces.C.int;
      Active_Bound          : Positive;
      First_Byte_Timeout_MS : Interfaces.Integer_64
        := Interfaces.Integer_64 (-1);
      Completion_Timeout_MS : Positive := Frame_Completion_Timeout_MS)
      return Ada.Streams.Stream_Element_Array;
   --  Receive exactly one bounded frame from a nonblocking stream socket.
   --  The first timeout may be indefinite. Once any byte arrives, the
   --  independent completion timeout covers the rest of the frame.

   procedure Send_Frame
     (Descriptor : Interfaces.C.int;
      Data       : Ada.Streams.Stream_Element_Array;
      Timeout_MS : Positive := Frame_Completion_Timeout_MS);
   --  Send exactly one frame through a nonblocking stream socket.

   procedure Set_Close_On_Exec (Descriptor : Interfaces.C.int);
   --  Prevent a control socket from crossing a later exec boundary.

   Extra_Data       : exception;
   Peer_Closed      : exception;
   Transport_Error  : exception;
   Transport_Timeout : exception;

end Spawn.Transport;
