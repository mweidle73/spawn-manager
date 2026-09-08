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

with Ada.Real_Time;
with GNAT.OS_Lib;
with Interfaces;
with System;

with Anet.Constants;

with Spawn.Protocol;

package body Spawn.Transport is

   package C renames Interfaces.C;

   use type Ada.Real_Time.Time;
   use type Ada.Streams.Stream_Element_Offset;
   use type C.int;
   use type C.long;
   use type Interfaces.Integer_64;
   use type Interfaces.Unsigned_16;

   type Poll_Item_Type is record
      Descriptor : C.int;
      Events     : C.short;
      Returned   : C.short;
   end record
     with Convention => C;

   function C_Poll
     (Items   : access Poll_Item_Type;
      Count   : C.unsigned_long;
      Timeout : C.int)
      return C.int
     with Import,
          Convention    => C,
          External_Name => "poll";

   function C_Recv
     (Descriptor : C.int;
      Buffer     : System.Address;
      Length     : C.size_t;
      Flags      : C.int)
      return C.long
     with Import,
          Convention    => C,
          External_Name => "recv";

   function C_Send
     (Descriptor : C.int;
      Buffer     : System.Address;
      Length     : C.size_t;
      Flags      : C.int)
      return C.long
     with Import,
          Convention    => C,
          External_Name => "send";

   type Deadline_Type is record
      Started    : Ada.Real_Time.Time;
      Timeout_MS : Interfaces.Integer_64;
   end record;

   function Has_Event (Returned : C.short; Event : Integer) return Boolean;
   --  Return True if poll reported Event.

   function Make_Deadline
     (Timeout_MS : Interfaces.Integer_64)
      return Deadline_Type;
   --  Construct a monotonic deadline, with -1 denoting no deadline.

   procedure Raise_OS_Error (Operation : String);
   --  Raise Transport_Error with the current errno diagnostic.

   procedure Read_Exact
     (Descriptor          :     C.int;
      Data                : in out Ada.Streams.Stream_Element_Array;
      Next                : in out Ada.Streams.Stream_Element_Offset;
      Started             : in out Boolean;
      First_Deadline      :     Deadline_Type;
      Completion_Deadline : in out Deadline_Type;
      Completion_MS       :     Positive);
   --  Fill Data from Next through Data'Last without resetting deadlines.

   procedure Reject_Extra_Data (Descriptor : C.int);
   --  Reject bytes already queued beyond the exact frame.

   function Remaining_Timeout (Deadline : Deadline_Type) return C.int;
   --  Return the rounded-up poll timeout for Deadline.

   procedure Wait_Ready
     (Descriptor : C.int;
      Events     : Integer;
      Deadline   : Deadline_Type);
   --  Wait until poll reports Events, closure or an error.

   function Has_Event (Returned : C.short; Event : Integer) return Boolean
   is
      Value : constant Interfaces.Unsigned_16
        := Interfaces.Unsigned_16 (Returned);
   begin
      return (Value and Interfaces.Unsigned_16 (Event)) /= 0;
   end Has_Event;

   -------------------------------------------------------------------------

   function Make_Deadline
     (Timeout_MS : Interfaces.Integer_64)
      return Deadline_Type
   is
   begin
      if Timeout_MS < -1 then
         raise Transport_Error with "invalid transport timeout";
      else
         return
           (Started    => Ada.Real_Time.Clock,
            Timeout_MS => Timeout_MS);
      end if;
   end Make_Deadline;

   -------------------------------------------------------------------------

   procedure Raise_OS_Error (Operation : String)
   is
   begin
      raise Transport_Error with Operation & ": "
        & GNAT.OS_Lib.Errno_Message (Err => GNAT.OS_Lib.Errno);
   end Raise_OS_Error;

   -------------------------------------------------------------------------

   procedure Read_Exact
     (Descriptor          :     C.int;
      Data                : in out Ada.Streams.Stream_Element_Array;
      Next                : in out Ada.Streams.Stream_Element_Offset;
      Started             : in out Boolean;
      First_Deadline      :     Deadline_Type;
      Completion_Deadline : in out Deadline_Type;
      Completion_MS       :     Positive)
   is
      Received : C.long;
   begin
      while Next <= Data'Last loop
         Wait_Ready
           (Descriptor => Descriptor,
            Events     => Anet.Constants.Sys.POLLIN,
            Deadline   =>
              (if Started then Completion_Deadline else First_Deadline));
         Received := C_Recv
           (Descriptor => Descriptor,
            Buffer     => Data (Next)'Address,
            Length     => C.size_t (Data'Last - Next + 1),
            Flags      => 0);
         if Received > 0 then
            if not Started then
               Started := True;
               Completion_Deadline := Make_Deadline
                 (Interfaces.Integer_64 (Completion_MS));
            end if;
            Next := Next + Ada.Streams.Stream_Element_Offset (Received);
         elsif Received = 0 then
            raise Peer_Closed with "peer closed during frame reception";
         elsif GNAT.OS_Lib.Errno /= Anet.Constants.Sys.EINTR
           and then GNAT.OS_Lib.Errno /= Anet.Constants.Sys.EAGAIN
         then
            Raise_OS_Error (Operation => "recv");
         end if;
      end loop;
   end Read_Exact;

   -------------------------------------------------------------------------

   function Receive_Frame
     (Descriptor            : C.int;
      Active_Bound          : Positive;
      First_Byte_Timeout_MS : Interfaces.Integer_64
        := Interfaces.Integer_64 (-1);
      Completion_Timeout_MS : Positive := Frame_Completion_Timeout_MS)
      return Ada.Streams.Stream_Element_Array
   is
      Header_Data : Ada.Streams.Stream_Element_Array
        (1 .. Spawn.Protocol.Header_Size) := (others => 0);
      Header              : Spawn.Protocol.Header_Type;
      Next                : Ada.Streams.Stream_Element_Offset := 1;
      Started             : Boolean := False;
      First_Deadline      : constant Deadline_Type
        := Make_Deadline (First_Byte_Timeout_MS);
      Completion_Deadline : Deadline_Type
        := (Started    => Ada.Real_Time.Time_First,
            Timeout_MS => Interfaces.Integer_64 (-1));
   begin
      Read_Exact
        (Descriptor          => Descriptor,
         Data                => Header_Data,
         Next                => Next,
         Started             => Started,
         First_Deadline      => First_Deadline,
         Completion_Deadline => Completion_Deadline,
         Completion_MS       => Completion_Timeout_MS);
      Spawn.Protocol.Decode_Header
        (Data         => Header_Data,
         Active_Bound => Active_Bound,
         Header       => Header);
      declare
         Length : constant Positive := Spawn.Protocol.Frame_Length
           (Payload_Length => Header.Payload_Length,
            Active_Bound   => Active_Bound);
         Frame : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Length)) := (others => 0);
      begin
         Frame (Header_Data'Range) := Header_Data;
         Next := Header_Data'Last + 1;
         Read_Exact
           (Descriptor          => Descriptor,
            Data                => Frame,
            Next                => Next,
            Started             => Started,
            First_Deadline      => First_Deadline,
            Completion_Deadline => Completion_Deadline,
            Completion_MS       => Completion_Timeout_MS);
         Reject_Extra_Data (Descriptor => Descriptor);
         return Frame;
      end;
   end Receive_Frame;

   -------------------------------------------------------------------------

   procedure Reject_Extra_Data (Descriptor : C.int)
   is
      Item : aliased Poll_Item_Type
        := (Descriptor => Descriptor,
            Events     => C.short (Anet.Constants.Sys.POLLIN),
            Returned   => 0);
      Poll_Result : C.int;
      Byte        : Ada.Streams.Stream_Element_Array (1 .. 1);
      Received    : C.long;
   begin
      loop
         Item.Returned := 0;
         Poll_Result := C_Poll
           (Items   => Item'Access,
            Count   => 1,
            Timeout => 0);
         if Poll_Result = 0 then
            return;
         elsif Poll_Result < 0 then
            if GNAT.OS_Lib.Errno /= Anet.Constants.Sys.EINTR then
               Raise_OS_Error (Operation => "poll after frame");
            end if;
         elsif Has_Event
           (Returned => Item.Returned,
            Event    => Anet.Constants.Sys.POLLNVAL)
         then
            raise Transport_Error with "invalid socket after frame";
         else
            Received := C_Recv
              (Descriptor => Descriptor,
               Buffer     => Byte'Address,
               Length     => 1,
               Flags      => Anet.Constants.Sys.MSG_PEEK);
            if Received > 0 then
               raise Extra_Data with "bytes queued beyond complete frame";
            elsif Received = 0
              or else GNAT.OS_Lib.Errno = Anet.Constants.Sys.EAGAIN
            then
               return;
            elsif GNAT.OS_Lib.Errno /= Anet.Constants.Sys.EINTR then
               Raise_OS_Error (Operation => "peek after frame");
            end if;
         end if;
      end loop;
   end Reject_Extra_Data;

   -------------------------------------------------------------------------

   function Remaining_Timeout (Deadline : Deadline_Type) return C.int
   is
      Elapsed_Duration : Duration;
      Elapsed_MS       : Interfaces.Integer_64;
      Remaining_MS     : Interfaces.Integer_64;
   begin
      if Deadline.Timeout_MS = -1 then
         return -1;
      end if;
      Elapsed_Duration := Ada.Real_Time.To_Duration
        (Ada.Real_Time.Clock - Deadline.Started);
      if Elapsed_Duration <= 0.0 then
         Remaining_MS := Deadline.Timeout_MS;
      else
         Elapsed_MS := Interfaces.Integer_64 (Elapsed_Duration * 1_000);
         if Elapsed_MS > 0 then
            Elapsed_MS := Elapsed_MS - 1;
         end if;
         Remaining_MS := Deadline.Timeout_MS - Elapsed_MS;
      end if;
      if Remaining_MS <= 0 then
         return 0;
      elsif Remaining_MS > Interfaces.Integer_64 (C.int'Last) then
         return C.int'Last;
      end if;
      return C.int (Remaining_MS);
   end Remaining_Timeout;

   -------------------------------------------------------------------------

   procedure Send_Frame
     (Descriptor : C.int;
      Data       : Ada.Streams.Stream_Element_Array;
      Timeout_MS : Positive := Frame_Completion_Timeout_MS)
   is
      Header : Spawn.Protocol.Header_Type;
      Next   : Ada.Streams.Stream_Element_Offset := Data'First;
      Sent   : C.long;
      Deadline : constant Deadline_Type := Make_Deadline
        (Interfaces.Integer_64 (Timeout_MS));
   begin
      if Data'Length < Spawn.Protocol.Header_Size then
         raise Transport_Error with "outbound frame is shorter than header";
      end if;
      Spawn.Protocol.Decode_Header
        (Data => Data
           (Data'First .. Data'First + Spawn.Protocol.Header_Size - 1),
         Active_Bound => Spawn.Protocol.Maximum_Frame_Size,
         Header       => Header);
      if Spawn.Protocol.Frame_Length
        (Payload_Length => Header.Payload_Length,
         Active_Bound   => Spawn.Protocol.Maximum_Frame_Size) /= Data'Length
      then
         raise Transport_Error with "outbound frame length mismatch";
      end if;

      while Next <= Data'Last loop
         Wait_Ready
           (Descriptor => Descriptor,
            Events     => Anet.Constants.Sys.POLLOUT,
            Deadline   => Deadline);
         Sent := C_Send
           (Descriptor => Descriptor,
            Buffer     => Data (Next)'Address,
            Length     => C.size_t (Data'Last - Next + 1),
            Flags      => Anet.Constants.Sys.MSG_NOSIGNAL);
         if Sent > 0 then
            Next := Next + Ada.Streams.Stream_Element_Offset (Sent);
         elsif Sent = 0 then
            raise Transport_Error with "send made no progress";
         elsif GNAT.OS_Lib.Errno /= Anet.Constants.Sys.EINTR
           and then GNAT.OS_Lib.Errno /= Anet.Constants.Sys.EAGAIN
         then
            Raise_OS_Error (Operation => "send");
         end if;
      end loop;
   end Send_Frame;

   -------------------------------------------------------------------------

   procedure Wait_Ready
     (Descriptor : C.int;
      Events     : Integer;
      Deadline   : Deadline_Type)
   is
      Item : aliased Poll_Item_Type
        := (Descriptor => Descriptor,
            Events     => C.short (Events),
            Returned   => 0);
      Result : C.int;
   begin
      loop
         Item.Returned := 0;
         Result := C_Poll
           (Items   => Item'Access,
            Count   => 1,
            Timeout => Remaining_Timeout (Deadline => Deadline));
         if Result = 0 then
            if Remaining_Timeout (Deadline => Deadline) = 0 then
               raise Transport_Timeout with "frame transport timed out";
            end if;
         elsif Result < 0 then
            if GNAT.OS_Lib.Errno /= Anet.Constants.Sys.EINTR then
               Raise_OS_Error (Operation => "poll");
            end if;
         elsif Has_Event
           (Returned => Item.Returned,
            Event    => Anet.Constants.Sys.POLLNVAL)
         then
            raise Transport_Error with "poll reported an invalid descriptor";
         elsif Has_Event (Returned => Item.Returned, Event => Events)
           or else Has_Event
             (Returned => Item.Returned,
              Event    => Anet.Constants.Sys.POLLERR)
           or else Has_Event
             (Returned => Item.Returned,
              Event    => Anet.Constants.Sys.POLLHUP)
         then
            return;
         end if;
      end loop;
   end Wait_Ready;

end Spawn.Transport;
