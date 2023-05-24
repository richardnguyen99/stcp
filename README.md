# Simple TCP

## Overview

This project is a collaboration project for SU CPSC 4510 Project 3, which
implements a simple TCP protocol.

### Collaborators

- [Richard Nguyen](mnguyen19@seattleu.edu)
- [Lolita Kim](lngo1@seattleu.edu)

### Submission files

- `README.md`: Project's overall description, explanation and other stuff.
- `transport.c`: Implementation of the simple TCP protocol.

### References

This project is based on the following references:

- SU CPSC 4510 Project 3: Simple TCP
- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/html/multi/index.html)
- [RFC 793](https://datatracker.ietf.org/doc/html/rfc793)
- [RFC 1122](https://datatracker.ietf.org/doc/html/rfc1122)
- [Chapter 3 (Transport layer) --- Computer Networking - A Top Down Approach](https://www.amazon.com/Computer-Networking-Top-Down-Approach-7th/dp/0133594149/ref=zg_bs_491302_sccl_17/136-1923250-5131831?psc=1)

## Implementation

The core implementation is based on 3 sections from the RFC 793:

1. TCP State Diagram:

   ```txt
                               +---------+ ---------\      active OPEN
                               |  CLOSED |            \    -----------
                               +---------+<---------\   \   create TCB
                                |     ^              \   \  snd SYN
                   passive OPEN |     |   CLOSE        \   \
                   ------------ |     | ----------       \   \
                    create TCB  |     | delete TCB         \   \
                                V     |                      \   \
                               +---------+            CLOSE    |    \
                               |  LISTEN |          ---------- |     |
                               +---------+          delete TCB |     |
                    rcv SYN      |     |     SEND              |     |
                   -----------   |     |    -------            |     V
   +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
   |         |<-----------------           ------------------>|         |
   |   SYN   |                    rcv SYN                     |   SYN   |
   |   RCVD  |<-----------------------------------------------|   SENT  |
   |         |                    snd ACK                     |         |
   |         |------------------           -------------------|         |
   +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
   |           --------------   |     |   -----------
   |                  x         |     |     snd ACK
   |                            V     V
   |  CLOSE                   +---------+
   | -------                  |  ESTAB  |
   | snd FIN                  +---------+
   |                   CLOSE    |     |    rcv FIN
   V                  -------   |     |    -------
   +---------+          snd FIN  /       \   snd ACK          +---------+
   |  FIN    |<-----------------           ------------------>|  CLOSE  |
   | WAIT-1  |------------------                              |   WAIT  |
   +---------+          rcv FIN  \                            +---------+
   | rcv ACK of FIN   -------   |                            CLOSE  |
   | --------------   snd ACK   |                           ------- |
   V        x                   V                           snd FIN V
   +---------+                  +---------+                   +---------+
   |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
   +---------+                  +---------+                   +---------+
   |                rcv ACK of FIN |                 rcv ACK of FIN |
   |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
   |  -------              x       V    ------------        x       V
   \ snd ACK                   +---------+delete TCB         +---------+
      ------------------------>|TIME WAIT|------------------>| CLOSED  |
                               +---------+                   +---------+

                       TCP Connection State Diagram
                               Figure 6.
   ```

   This diagram dictates our team's connection states:

   ```c
   enum
   {
       CSTATE_LISTEN,
       CSTATE_SYN_SENT,
       CSTATE_SYN_RCVD,
       CSTATE_ESTABLISHED,
       CSTATE_CLOSE_WAIT,
       CSTATE_LAST_ACK,
       CSTATE_FIN_WAIT_1,
       CSTATE_FIN_WAIT_2,
       CSTATE_CLOSING,
       CSTATE_TIME_WAIT,
       CSTATE_CLOSED
   };
   ```

   Some of them are used to actually implement the STCP. Others are used as
   illustrations so that our team can tell what's state we're at.

2. Sequence Variables

   ```txt
    Send Sequence Variables

      SND.UNA - send unacknowledged
      SND.NXT - send next
      SND.WND - send window
      SND.UP  - send urgent pointer
      SND.WL1 - segment sequence number used for last window update
      SND.WL2 - segment acknowledgment number used for last window
                update
      ISS     - initial send sequence number

    Receive Sequence Variables

      RCV.NXT - receive next
      RCV.WND - receive window
      RCV.UP  - receive urgent pointer
      IRS     - initial receive sequence number

    Current Segment Variables

      SEG.SEQ - segment sequence number
      SEG.ACK - segment acknowledgment number
      SEG.LEN - segment length
      SEG.WND - segment window
      SEG.UP  - segment urgent pointer
      SEG.PRC - segment precedence value
   ```

   Sequence variables are our next core component in the implementation. They
   are used to guard-check and adjust windows. Same as TCP State Diagram, they
   also determine what data field we have in the `context_t` struct:

   ```c
    typedef struct
    {
        bool_t done;

        int connection_state; /* state of the connection (established, etc.) */
        tcp_seq initial_sequence_num;

        tcp_seq snd_una;
        tcp_seq snd_nxt;
        tcp_seq snd_wnd;

        tcp_seq rcv_nxt;
        tcp_seq rcv_wnd;

    } context_t;
   ```

   However, not all sequence variables from RFC 793 are used here. Some of them
   are useful for restrasmissions, time out, delay, etc. Since this project does
   not require us to deal with those problems, we decide to drop them for
   simplicity.

3. Event processing:

   The final focus is based on the [Event Processing 3.9](https://www.rfc-editor.org/rfc/rfc793#section-3.9).
   We use this section as the reference point to deal with establishing
   connections and handling different packets. We also add some guard-checks
   and window adjusting mechanism based on it.

   - For establishing connections, we mainly use `OPEN Call` and `SEGMENT arrive`
     sections (but not only).
   - For handling packets, we mainly use `SEGMENT arrive` section.

   Alongside with event processing, we also use some mechanism to manage window
   from [Data Communication 3.7](https://www.rfc-editor.org/rfc/rfc793#section-3.7).

## Strength

1. Our implementation is based on closely what's described in RFC 793.
2. There are a lot of guard checks to make sure we accept correct segments. From
   RFC, they are mainly used to check for duplicate ACK, etc. We adopt that and
   make sure we can follow and test it.
3. Our implementation utilizes the `stcp_api.h` for most functionalities,
   including utility functions such as `MIN`, and network functions such as
   `stcp_network_recv`.
4. We double-checked our code and made sure there was no obvious memory leak.

## Weaknesses

1. A lot of `goto` statements are used. We find it handy but it might be hard to
   follow if first exposed.
2. Memory leak is checked manually (no `valgrind`).
3. No congestion control, no retransmission, time out, delay, out of order, etc.
4. File types tested are only (all passed with `diff`):
   - Text files (all source files from this project).
   - Object files (all object files built from this project).
