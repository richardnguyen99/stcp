/*
 * transport.c
 *
 * CPSC4510: Project 3 (STCP)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file.
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

#define STCP_OFFSET 5
#define STCP_WINDOW_SIZE 3072
#define STCP_MTU sizeof(STCPHeader) + STCP_MSS

#define HANDLE_HANDSHAKE(cond)                 \
    if (!(cond))                               \
    {                                          \
        errno = ECONNREFUSED;                  \
        ctx->connection_state = CSTATE_CLOSED; \
        ctx->done = TRUE;                      \
        goto established;                      \
    }

#define HANDLE_SEGMENT_ARRIVE(cond) \
    if (!(cond))                    \
    {                               \
        goto handle_close_packet;   \
    }

/* Possible use states. */
/* Not all of them are used in this implementation. They are from TCP State
 * Transition Diagram in RFC 793.
 */
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
}; /* obviously you should have more states */

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done; /* TRUE once connection is closed */

    int connection_state; /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;

    tcp_seq snd_una; /* Send Unacknowledged */
    tcp_seq snd_nxt; /* Send Next */
    tcp_seq snd_wnd; /* Segment Window */

    tcp_seq rcv_nxt; /* Receive Next */
    tcp_seq rcv_wnd; /* Receive Window */

} context_t;

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);

bool_t send_syn(mysocket_t sd, context_t *ctx);
bool_t wait_for_synack(mysocket_t sd, context_t *ctx);

bool_t wait_for_syn(mysocket_t sd, context_t *ctx);

ssize_t send_packet(mysocket_t sd, context_t *ctx, char *buffer, size_t buffer_len, uint8_t th_flags);

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *)calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

    ctx->snd_una = ctx->initial_sequence_num;
    ctx->snd_nxt = ctx->snd_una;
    ctx->rcv_wnd = STCP_WINDOW_SIZE;

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

    /**
     * These connection state transitions are only for illustration so that
     * we can keep track of the state of the connection. It can be converted to
     * a finite-state machine by using a combination of  while and switch-case
     * statements.
     */

    /* From sender (application layer) */
    if (is_active)
    {
        ctx->connection_state = CSTATE_CLOSED;

        while (ctx->connection_state != CSTATE_ESTABLISHED)
        {
            switch (ctx->connection_state)
            {
            case CSTATE_CLOSED:
                HANDLE_HANDSHAKE(send_syn(sd, ctx));

                ctx->connection_state = CSTATE_SYN_SENT;
                break;

            case CSTATE_SYN_SENT:
                HANDLE_HANDSHAKE(wait_for_synack(sd, ctx));
                HANDLE_HANDSHAKE(send_packet(sd, ctx, NULL, 0, TH_ACK) != -1);

                ctx->connection_state = CSTATE_ESTABLISHED;
                break;

            default:
                HANDLE_HANDSHAKE(FALSE);
                break;
            }
        }

        goto established;
    }

    /* From network (network layer) */
    ctx->connection_state = CSTATE_LISTEN;

    while (ctx->connection_state != CSTATE_ESTABLISHED)
    {
        switch (ctx->connection_state)
        {
        case CSTATE_LISTEN:
            HANDLE_HANDSHAKE(wait_for_syn(sd, ctx));

            ctx->connection_state = CSTATE_SYN_RCVD;
            break;

        case CSTATE_SYN_RCVD:
            HANDLE_HANDSHAKE(send_packet(sd, ctx, NULL, 0, TH_SYN | TH_ACK) != -1);
            ctx->snd_nxt += 1;

            goto established;
            break;

        default:
            HANDLE_HANDSHAKE(FALSE);
            break;
        }
    }

established:
    stcp_unblock_application(sd);
    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}

/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    ctx->initial_sequence_num = rand() % 256;
#endif
}

/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);
    assert(!ctx->done);

    while (!ctx->done)
    {
        unsigned int event;

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        /* Application Layer wants to send data out */
        if (event & APP_DATA)
        {
            uint32_t available_snd_wnd = ctx->snd_una + ctx->snd_wnd - ctx->snd_nxt;

            if (available_snd_wnd > 0)
            {
                size_t payload_len = MIN(available_snd_wnd, STCP_MSS);
                char *payload = (char *)calloc(1, sizeof(char) * payload_len);
                payload_len = stcp_app_recv(sd, payload, payload_len);

                send_packet(sd, ctx, payload, payload_len, TH_ACK);
                free(payload);
            }
        }

        /* Network Layer wants to send data to app */
        if (event & NETWORK_DATA)
        {
            uint8_t *pkt = (uint8_t *)calloc(1, STCP_MTU);
            ssize_t pktlen = stcp_network_recv(sd, pkt, STCP_MTU);
            STCPHeader *hdr = (STCPHeader *)pkt;

            HANDLE_SEGMENT_ARRIVE(ctx->rcv_nxt == ntohl(hdr->th_seq));
            ctx->rcv_nxt += pktlen - TCP_DATA_START(pkt);

            tcp_seq seg_ack = ntohl(hdr->th_ack);

            if (!(hdr->th_flags & TH_ACK))
                goto not_ack;

            if (ctx->connection_state == CSTATE_SYN_RCVD)
            {
                HANDLE_SEGMENT_ARRIVE(ctx->snd_una <= seg_ack);
                HANDLE_SEGMENT_ARRIVE(seg_ack <= ctx->snd_nxt);
                ctx->connection_state = CSTATE_ESTABLISHED;
                ctx->snd_una = seg_ack;
            }
            else
            {
                HANDLE_SEGMENT_ARRIVE(seg_ack <= ctx->snd_nxt);
                ctx->snd_una = seg_ack;

                switch (ctx->connection_state)
                {
                case CSTATE_FIN_WAIT_1:
                    ctx->connection_state = CSTATE_FIN_WAIT_2;
                    break;

                case CSTATE_CLOSING:
                case CSTATE_LAST_ACK:
                    ctx->connection_state = CSTATE_CLOSED;
                    ctx->done = TRUE;
                    break;
                }
            }

        not_ack:
            /* Send data to Application Layer */
            stcp_app_send(sd, pkt + TCP_DATA_START(pkt), pktlen - TCP_DATA_START(pkt));

            if ((hdr->th_flags & TH_FIN) || (pktlen - TCP_DATA_START(pkt) > 0))
            {

                if (!(hdr->th_flags & TH_FIN))
                    goto not_fin;

                ctx->snd_una += 1;
                ctx->rcv_nxt += 1;

                stcp_fin_received(sd);

                switch (ctx->connection_state)
                {
                case CSTATE_ESTABLISHED:
                    ctx->connection_state = CSTATE_CLOSE_WAIT;
                    break;

                case CSTATE_FIN_WAIT_1:
                    ctx->connection_state = CSTATE_CLOSING;
                    break;

                case CSTATE_FIN_WAIT_2:
                    ctx->connection_state = CSTATE_CLOSED;
                    ctx->done = TRUE;
                    break;

                default:
                    break;
                }

            not_fin:
                send_packet(sd, ctx, NULL, 0, TH_ACK);
            }

            free(pkt);
        }

    handle_close_packet:
        if (event & APP_CLOSE_REQUESTED)
        {
            switch (ctx->connection_state)
            {
            case CSTATE_ESTABLISHED:
                ctx->connection_state = CSTATE_FIN_WAIT_1;
                break;

            case CSTATE_CLOSE_WAIT:
                ctx->connection_state = CSTATE_LAST_ACK;
                break;

            default:
                break;
            }

            send_packet(sd, ctx, NULL, 0, TH_FIN);
        }
    }
}

/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 *
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format, ...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}

ssize_t send_packet(mysocket_t sd, context_t *ctx, char *buffer, size_t buffer_len, uint8_t th_flags)
{
    size_t pktlen = sizeof(STCPHeader) + buffer_len;
    char *pkt = (char *)calloc(1, pktlen);
    assert(pkt);

    STCPHeader *hdr = (STCPHeader *)pkt;
    assert(hdr);

    // Do not change this except for SYN packet.
    // If you need to change it otherwise, you messed up somewhere.
    hdr->th_seq = htonl(ctx->snd_nxt);
    hdr->th_ack = htonl(ctx->rcv_nxt);

    hdr->th_off = STCP_OFFSET;
    hdr->th_flags = th_flags;
    hdr->th_win = htons(ctx->rcv_wnd);

    if (buffer != NULL)
    {
        memcpy(pkt + TCP_DATA_START(pkt), buffer, buffer_len);
        ctx->snd_nxt += buffer_len;
    }

    ssize_t success = stcp_network_send(sd, pkt, pktlen, NULL);

    if (th_flags & TH_FIN)
        ctx->snd_nxt += 1;

    free(pkt);
    return success;
}
bool_t send_syn(mysocket_t sd, context_t *ctx)
{

    STCPHeader *hdr = (STCPHeader *)calloc(1, sizeof(STCPHeader));
    assert(hdr);

    hdr->th_seq = htonl((ctx->snd_nxt)++);
    hdr->th_off = STCP_OFFSET;
    hdr->th_flags = TH_SYN;
    hdr->th_win = htons(ctx->rcv_wnd);

    ssize_t success = stcp_network_send(sd, hdr, sizeof(STCPHeader), NULL);
    free(hdr);

    return (success > 0);
}

bool_t wait_for_synack(mysocket_t sd, context_t *ctx)
{
    bool_t ret = FALSE;
    char *pkt = NULL;

    uint event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

    if (!(event & NETWORK_DATA))
        return FALSE;

    {
        pkt = (char *)calloc(1, STCP_MTU);
        ssize_t pktlen = stcp_network_recv(sd, pkt, STCP_MTU);

        if (pktlen < 0)
            goto cleanup;

        if ((size_t)pktlen < sizeof(STCPHeader))
            goto cleanup;

        STCPHeader *hdr = (STCPHeader *)pkt;

        tcp_seq seg_ack = ntohl(hdr->th_ack);
        tcp_seq seg_seq = ntohl(hdr->th_seq);
        uint16_t seg_wnd = ntohs(hdr->th_win);

        if (!(hdr->th_flags & (TH_SYN | TH_ACK)))
            goto cleanup;

        if (ctx->snd_una >= seg_ack)
            goto cleanup;

        if (seg_ack > ctx->snd_nxt)
            goto cleanup;

        ctx->snd_una = seg_ack;
        ctx->rcv_nxt = seg_seq + 1;
        ctx->snd_wnd = MIN(seg_wnd, STCP_WINDOW_SIZE);

        ret = TRUE;
    }

cleanup:
    if (pkt)
        free(pkt);

    return ret;
}

bool_t wait_for_syn(mysocket_t sd, context_t *ctx)
{
    bool_t ret = FALSE;
    char *pkt = NULL;

    uint event = stcp_wait_for_event(sd, ANY_EVENT, NULL);
    if (!(event & NETWORK_DATA))
        return FALSE;

    {
        pkt = (char *)calloc(1, STCP_MTU);
        ssize_t pktlen = stcp_network_recv(sd, pkt, STCP_MTU);

        if (pktlen < 0)
            goto cleanup;

        if ((unsigned)pktlen < sizeof(STCPHeader))
            goto cleanup;

        STCPHeader *hdr = (STCPHeader *)pkt;

        if (!(hdr->th_flags & TH_SYN))
            goto cleanup;

        ctx->rcv_nxt = ntohl(hdr->th_seq);
        ctx->snd_wnd = MIN(ntohs(hdr->th_win), STCP_WINDOW_SIZE);
        ctx->rcv_nxt += 1;

        ret = TRUE;
    }

cleanup:
    if (pkt)
        free(pkt);

    return ret;
}
