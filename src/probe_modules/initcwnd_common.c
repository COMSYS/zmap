#include "initcwnd_common.h"

uint32_t num_ports;

skipList* myList;

uint8_t mss_retries;
uint16_t* mss_buf;

int initcwnd_global_initialize(struct state_conf* state)
{
    num_ports = state->source_port_last - state->source_port_first + 1;

    // init state machine
    uint32_t statesize = zconf.rate * 10; // set this to 50000 (http)?
    if (statesize < 10000) {
        statesize = 10000;
    }

    state_myinit(statesize, 15); // timeout in seconds

    char* args = NULL;
    if (!state->probe_args || !*(args = strdup(state->probe_args))) {
        log_info("initcwnd", "Missing MSS arg, using [64]");
        mss_retries = 1;
        mss_buf = malloc(sizeof(uint16_t));
        mss_buf[0] = 64;
    } else {
        mss_retries = 1;
        int i = 0;
        while (args[i] != 0) {
            if (args[i] == ':') {
                mss_retries++;
            }
            i++;
        }

        mss_buf = malloc(sizeof(uint16_t) * mss_retries);
        i = 0;
        char* c = args;
        while (i < mss_retries && *args) {
            mss_buf[i++] = (uint16_t)strtol(c, &c, 10);
            log_info("initcwnd", "Found MSS [%d]", mss_buf[i - 1]);
            if (*c != ':') {
                break;
            }
            c++;
        }
    }
    if (args) {
        free(args);
    }

    log_debug("initcwnd", "initialize Skiplist");
    myList = create_InputTable();
    FILE* stream = fopen("a", "r");
    if (stream == NULL) {
        log_error("initcwnd", "could not open data file, proceeding without data input");
        return EXIT_SUCCESS;
    }

    char ip[64];
    char buf[1024];
    char info[1024];
    struct in_addr ipstruct;

    while (fgets(buf, sizeof(buf), stream)) {
        memset(ip, 0, 64);
        memset(info, 0, 1024);
        sscanf(buf, "%[^,], %[^,]", ip, info);

        // convert to uint32_t
        if (inet_aton(ip, &ipstruct) != 1) {
            continue;
        }

        uint32_t ipint = ntohl(ipstruct.s_addr);
        // allocate memory for string and copy
        // we don't want the \n symbol
        if (strlen(info) == 0) {
            continue;
        }

        uint16_t length = strlen(info);
        char* tmp = malloc(length + 1);
        strncpy(tmp, info, length);
        tmp[length] = '\0';
        if (tmp[length - 1] == '\n') {
            tmp[length - 1] = '\0';
        }
        
        // input into skiplist
        //log_debug("initcwnd", "%s", "%s", ip, tmp);
        insert_InputTable(myList, ipint, tmp);
        // reset
    }

    fclose(stream);
    log_debug("initcwnd", "Skiplist data read in, create links");
    link_InputTable(myList);
    log_debug("initcwnd", "Skiplist finished.");

    return EXIT_SUCCESS;
}

int initcwnd_pcap_filter(char* out_filter, size_t max_len)
{
    unsigned int len = snprintf(out_filter, 0, "tcp src port %d", zconf.target_port);

    if (len <= max_len) {
        snprintf(out_filter, max_len, "tcp src port %d", zconf.target_port);
        return 0;
    }

    return -1;
}

int initcwnd_init_perthread(void* buf, macaddr_t* src, macaddr_t* gw, port_h_t dst_port, __attribute__((unused)) void** arg_ptr)
{
    memset(buf, 0, MAX_PACKET_SIZE);
    struct ether_header* eth_header = (struct ether_header*)buf;
    make_eth_header(eth_header, src, gw);
    struct ip* ip_header = (struct ip*)(&eth_header[1]);
    uint16_t len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + 4);
    make_ip_header(ip_header, IPPROTO_TCP, len);
    struct tcphdr* tcp_header = (struct tcphdr*)(&ip_header[1]);
    make_tcp_header(tcp_header, dst_port, TH_SYN);
    return (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
}

void initcwnd_print_packet(FILE *fp, void* packet)
{
    struct ether_header* ethh = (struct ether_header*)packet;
    struct ip* iph = (struct ip*)&ethh[1];
    struct tcphdr* tcph = (struct tcphdr*)&iph[1];
    fprintf(fp, "tcp { source: %u | dest: %u | seq: %u | checksum: %u }\n",
            ntohs(tcph->th_sport),
            ntohs(tcph->th_dport),
            ntohl(tcph->th_seq),
            ntohl(tcph->th_sum));
    fprintf_ip_header(fp, iph);
    fprintf_eth_header(fp, ethh);
    fprintf(fp, "------------------------------------------------------\n");
}

int initcwnd_make_packet(void* buf, UNUSED size_t *buf_len, ipaddr_n_t src_ip, ipaddr_n_t dst_ip, uint32_t* validation, int probe_num, __attribute__((unused)) void* arg)
{
    struct ether_header* eth_header = (struct ether_header*)buf;
    struct ip* ip_header = (struct ip*)(&eth_header[1]);
    struct tcphdr* tcp_header = (struct tcphdr*)(&ip_header[1]);
    unsigned char* options = (unsigned char*)(&tcp_header[1]);
    
    uint32_t tcp_seq = validation[0];

    ip_header->ip_src.s_addr = src_ip;
    ip_header->ip_dst.s_addr = dst_ip;
    ip_header->ip_off |= htons(IP_DF);

    tcp_header->th_sport = htons(get_src_port(num_ports, probe_num, validation));
    tcp_header->th_seq = tcp_seq;
    tcp_header->th_sum = 0;
    tcp_header->th_off = 6; // 5 + 1 = 4 bytes more for options
    // tcp_header->th_off = 7; // 5 + 2 = 8 bytes more for options SACK

    // MSS OPTION
    options[0] = 2;
    options[1] = 4;
    uint16_t mss = mss_buf[probe_num % mss_retries];
    *(uint16_t*)&options[2] = htons(mss);

    // SACK PERMITTED
    /* 
    options[4] = 4;
    options[5] = 2;
    options[6] = 0;
    options[7] = 0;
    */

    tcp_header->th_sum = tcp_checksum(sizeof(struct tcphdr) + 4, // + 4 bytes for options
    ip_header->ip_src.s_addr, ip_header->ip_dst.s_addr, tcp_header);
    // tcp_header->th_sum = tcp_checksum(sizeof(struct tcphdr) + 8, // + 8 bytes for options
    //        ip_header->ip_src.s_addr, ip_header->ip_dst.s_addr, tcp_header);
    
    ip_header->ip_sum = 0;
    ip_header->ip_sum = zmap_ip_checksum((unsigned short*)ip_header);

    return EXIT_SUCCESS;
}

int initcwnd_validate_packet(const struct ip* ip_hdr, uint32_t len, __attribute__((unused)) uint32_t* src_ip, __attribute__((unused)) uint32_t* validation)
{
    if (ip_hdr->ip_p != IPPROTO_TCP) {
        return 0;
    }

    if ((4 * ip_hdr->ip_hl + sizeof(struct tcphdr)) > len) {
        // buffer not large enough to contain the expected tcp header
        return 0;
    }

    struct tcphdr *tcp = (struct tcphdr*)((char*)ip_hdr + 4 * ip_hdr->ip_hl);
    uint16_t sport = tcp->th_sport;
    uint16_t dport = tcp->th_dport;

    // validate source port
    if (ntohs(sport) != zconf.target_port) {
        return 0;
    }

    pthread_mutex_lock(&statetable_lock);
    struct StateData* stateptr = get_StateData(ip_hdr->ip_src.s_addr, ntohs(dport), myStateTable);
    pthread_mutex_unlock(&statetable_lock);

    if (stateptr != NULL) {
        return 1;
    }

    return 1;
}

void initcwnd_copy(const u_char* packet, struct initcwnd_Data* data_ptr)
{
    struct ip* ip_hdr = (struct ip*)&packet[sizeof(struct ether_header)];
    struct tcphdr* tcp = (struct tcphdr*)((char*)ip_hdr + ip_hdr->ip_hl * 4);
    uint32_t payload = ntohs(ip_hdr->ip_len) - sizeof(struct ip) - tcp->th_off * 4;
    uint32_t max_payload = TCP_SNAPLEN - sizeof(struct ether_header) - sizeof(struct ip) - tcp->th_off * 4;

    if (payload > max_payload) {
        payload = max_payload;
    }

    u_char* payload_ptr = (u_char*)tcp + tcp->th_off * 4;
    uint32_t offset = ntohl(tcp->th_seq) - data_ptr->seq_start;
    // something wrong with the seq numbers ?
    if (offset > BUFFERSIZE) {
        return;
    }

    // copy data, if space available
    // this also accounts for reorders
    if (offset + payload < BUFFERSIZE - 1 && payload > 0) {
        memcpy(data_ptr->buffer + offset, payload_ptr, payload);
        if (offset + payload > data_ptr->buf_offset) {
            data_ptr->buf_offset = offset + payload;
            data_ptr->buffer[data_ptr->buf_offset] = '\0';
        }
        // log_debug("initcwnd", data_ptr->buffer);
    }
}

void initcwnd_create_stateinfo(uint32_t src_ip, struct tcphdr* tcp, uint16_t offset, int probe_num)
{
    pthread_mutex_lock(&statetable_lock);
    struct StateData* dataptr = insert_StateData(src_ip, ntohs(tcp->th_dport), myStateTable);
    pthread_mutex_unlock(&statetable_lock);

    if (dataptr != NULL) {
        pthread_mutex_lock(&dataptr->state_lock);
        dataptr->state = STATE_SYNACK;
        dataptr->sqn = ntohl(tcp->th_ack) + offset;
        dataptr->ssqn = ntohl(tcp->th_seq) + 1;
        dataptr->estimated_mss = 0;
        dataptr->reported_mss = 0; // if nothing is reported, this is the default MSS

        // store the probe_number so we can report it later
        dataptr->probe_num = probe_num;
        pthread_mutex_unlock(&dataptr->state_lock);
    }
}

void initcwnd_process_SYNACK(struct tcphdr* tcp, struct ip* ip_hdr, ringbuffer_t* ring, const u_char* packet, int probe_num, packet_builder builder)
{
    uint8_t* data = NULL;
    uint32_t this_len;

    ringbuffer_lock(ring);

    if ((this_len = ringbuffer_reserve(ring, &data, NULL)) == 0) {
        log_error("initcwnd", "ring full sending ACK after SYNACK");
        ringbuffer_unlock(ring);
        return;
    }

    this_len = tcp_buildAck(packet, data, this_len);
    ringbuffer_commit(ring, this_len);
    ringbuffer_unlock(ring);

    ringbuffer_lock(ring);


    u_char* buf2 = NULL;
    if ((this_len = ringbuffer_reserve(ring, &buf2, NULL)) == 0) {
        log_error("initcwnd", "ring full sending packet after SYNACK");
        ringbuffer_unlock(ring);
        return;
    }

    struct ip* ip_hdrs2 = (struct ip*)&buf2[sizeof(struct ether_header)];
    struct tcphdr* tcps2 = (struct tcphdr*)((char*)ip_hdrs2 + 4 * ip_hdrs2->ip_hl);
    tcps2->th_seq = tcp->th_ack;
    tcps2->th_ack = htonl(ntohl(tcp->th_seq) + 1);

    tcps2->th_off = 5;
    tcps2->th_flags = TH_ACK | TH_PUSH;
    ip_hdrs2->ip_dst = ip_hdr->ip_src;
    ip_hdrs2->ip_src = ip_hdr->ip_dst;
    tcps2->th_sport = tcp->th_dport;
    tcps2->th_dport = tcp->th_sport;
    tcps2->th_win = htons(65535);

    char* payload = (char*)tcps2 + tcps2->th_off * 4;

    uint16_t payload_length = builder(payload, ip_hdr->ip_src.s_addr);

    ip_hdrs2->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + payload_length);

    tcps2->th_sum = 0;
    tcps2->th_sum = tcp_checksum(sizeof(struct tcphdr) + payload_length, ip_hdrs2->ip_src.s_addr, ip_hdrs2->ip_dst.s_addr, tcps2);

    ip_hdrs2->ip_sum = 0;
    ip_hdrs2->ip_sum = zmap_ip_checksum((unsigned short*) ip_hdrs2);

    ringbuffer_commit(ring, sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + payload_length);
    ringbuffer_unlock(ring);

    initcwnd_create_stateinfo(ip_hdr->ip_src.s_addr, tcp, payload_length, probe_num);
}

int initcwnd_process_RST(uint32_t src_ip, struct tcphdr* tcp, struct StateData* ptr, fieldset_t* fs, const u_char* packet, ringbuffer_t* ring, redirect_function redirect)
{
    if (ptr != NULL) {
        fs_add_string(fs, "classification", (char*)"RST DATA", 0);
        if (ptr->info != NULL) {
            // try redirect?
            if (((ptr->state & STATE_LOCATION) == 0 || (ptr->state & STATE_LOCATION_LONG) == 0)) {
                // not redirected yet
                if (redirect(packet, src_ip, ntohs(tcp->th_dport), ring) == EXIT_SUCCESS) {
                    return EXIT_FAILURE;
                }
            }
            if ((ptr->state & (STATE_LOCATION | STATE_LOCATION_LONG)) == 0) {
                // not in any redirect state
                struct initcwnd_Data* payload_ptr = (struct initcwnd_Data*)ptr->info;
                fs_add_uint64(fs, "success", 0);
                fs_add_uint64(fs, "packets", payload_ptr->packets);
                fs_add_uint64(fs, "payload", payload_ptr->bytes);
            } else {
                fs_add_uint64(fs, "success", 0);
                fs_add_uint64(fs, "packets", 0);
                fs_add_uint64(fs, "payload", 0);
            }
        } else {
            // server resets before sending payload (after GET)
            fs_add_uint64(fs, "success", 0);
            fs_add_uint64(fs, "packets", 0);
            fs_add_uint64(fs, "payload", 0);
        }

        fs_add_uint64(fs, "probe_num", ptr->probe_num / mss_retries);
        fs_add_uint64(fs, "req_mss", mss_buf[ptr->probe_num % mss_retries]);

        // end the connection
        pthread_mutex_lock(&statetable_lock);
        remove_StateData(src_ip, ntohs(tcp->th_dport), myStateTable);
        pthread_mutex_unlock(&statetable_lock);
    } else {
        fs_add_string(fs, "classification", (char*) "RST SYN", 0);
        fs_add_uint64(fs, "success", 0);
        fs_add_uint64(fs, "packets", 0);
        fs_add_uint64(fs, "payload", 0);

        fs_add_uint64(fs, "probe_num", 0xFFFFFFFFFFFFFFFF);
        fs_add_uint64(fs, "req_mss", 0);
    }

    fs_add_string(fs, "completed", (char*)"", 0);
    fs_add_uint64(fs, "assumption", 0);
    return EXIT_SUCCESS;
}

void initcwnd_process_first_segment(const u_char* packet, struct StateData* ptr, struct tcphdr* tcp, uint32_t payload)
{
    pthread_mutex_lock(&ptr->state_lock);
    if (ptr->info != NULL) {
        log_error("initcwnd", "ptr->info must be NULL in first segment");
        free(ptr->info);
        ptr->info = NULL;
    }
    // Create our struct to hold relevant data
    struct initcwnd_Data* payload_ptr = malloc(sizeof(struct initcwnd_Data));
    if (payload_ptr == NULL) {
        log_error("initcwnd", "Out of memory allocating struct (first segment)?");
        pthread_mutex_unlock(&ptr->state_lock);
        return;
    }
    memset(payload_ptr, 0, sizeof(struct initcwnd_Data));
    ptr->info = payload_ptr;
    payload_ptr->bytes = payload;

    // this is the first data packet, so this should estimate our MSS
    ptr->estimated_mss = payload;
    payload_ptr->len_high_seq_pack = payload;

    payload_ptr->packets = 1;
    payload_ptr->seq = ntohl(tcp->th_seq);
    payload_ptr->seq_start = ptr->ssqn;
    payload_ptr->seq_iterator = 0;
    payload_ptr->seq_array[payload_ptr->seq_iterator] = ntohl(tcp->th_seq);
    payload_ptr->seq_iterator++;
    payload_ptr->buf_offset = 0;
    payload_ptr->requests = 1;

    initcwnd_copy(packet, payload_ptr);
    pthread_mutex_unlock(&ptr->state_lock);
}

int initcwnd_process_unknown_packet(const u_char* packet, __attribute__((unused)) struct tcphdr* tcp, ringbuffer_t* ring, __attribute((unused)) fieldset_t* fs)
{
    uint8_t* data = NULL;
    uint32_t this_len;

    ringbuffer_lock(ring);

    if ((this_len = ringbuffer_reserve(ring, &data, &this_len)) == 0) {
        log_error("initcwnd", "ring full sending RST after unknown");
        ringbuffer_unlock(ring);
        return EXIT_FAILURE;
    } else {
        this_len = tcp_buildRst(packet, data, this_len);
        ringbuffer_commit(ring, this_len);
    }

    ringbuffer_unlock(ring);
    return EXIT_FAILURE;
}

int initcwnd_process_known_connection(const u_char* packet, uint32_t src_ip, struct StateData* ptr, struct ip* ip_hdr, struct tcphdr* tcp, ringbuffer_t* ring, fieldset_t* fs, redirect_function redirect, redirect_synack_processor synack_redirected)
{
    // We have a syn ack for a redirected connection -> use the known location
    if (tcp->th_flags & TH_ACK && tcp->th_flags & TH_SYN && ((ptr->state & STATE_LOCATION) > 0 || (ptr->state & STATE_LOCATION_LONG) > 0) && ptr->info != NULL) {
        return synack_redirected(ip_hdr, tcp, ptr, ring);
    } else {
        // No syn-ack or new connection
        uint32_t payload = tcp_getPayloadLength(packet);
        // we have data
        if (payload > 0) {
            // this is the first data we ever saw for this connection
            if (ptr->info == NULL) {
                initcwnd_process_first_segment(packet, ptr, tcp, payload);
            } else {
                // we already have data from this connection
                struct initcwnd_Data* payload_ptr = (struct initcwnd_Data*)ptr->info;

                // more than the allowed number of packets ?
                if (payload_ptr->packets >= MAX_PACKETS) {
                    fs_add_string(fs, "classification", (char*)"Too many packets", 0);
                    fs_add_uint64(fs, "success", 1);
                    fs_add_uint64(fs, "packets", payload_ptr->packets);
                    fs_add_uint64(fs, "payload", payload_ptr->bytes);
                    fs_add_string(fs, "completed", (char*)"ok", 0);

                    fs_add_uint64(fs, "assumption", 0);
                    fs_add_uint64(fs, "probe_num", ptr->probe_num / mss_retries);
                    fs_add_uint64(fs, "req_mss", mss_buf[ptr->probe_num % mss_retries]);

                    uint8_t* data = NULL;
                    uint32_t this_len;

                    ringbuffer_lock(ring);

                    if ((this_len = ringbuffer_reserve(ring, &data, &this_len)) == 0) {
                        log_error("initcwnd", "ring full sending RST (Too many packets)");
                        ringbuffer_unlock(ring);
                        return EXIT_FAILURE;
                    } else {
                        this_len = tcp_buildRst(packet, data, this_len);
                        ringbuffer_commit(ring, this_len);
                    }

                    ringbuffer_unlock(ring);
                    pthread_mutex_lock(&statetable_lock);
                    remove_StateData(src_ip, ntohs(tcp->th_dport), myStateTable);
                    pthread_mutex_unlock(&statetable_lock);
                    return EXIT_SUCCESS;
                }
                // more data than our buffer can hold ?
                if (ntohl(tcp->th_seq) - ptr->ssqn >= BUFFERSIZE) {
                    fs_add_string(fs, "classification", (char*)"Buffer overflow", 0);
                    fs_add_uint64(fs, "success", 1);
                    fs_add_uint64(fs, "packets", payload_ptr->packets);
                    fs_add_uint64(fs, "payload", payload_ptr->bytes);

                    fs_add_uint64(fs, "assumption", 0);
                    fs_add_uint64(fs, "probe_num", ptr->probe_num / mss_retries);
                    fs_add_uint64(fs, "req_mss", mss_buf[ptr->probe_num % mss_retries]);
                    return EXIT_FAILURE;
                }

                pthread_mutex_lock(&ptr->state_lock);
                uint32_t old_seq = payload_ptr->seq;
                uint32_t old_len = payload_ptr->len_high_seq_pack;
                // seq nr smaller than the biggest we have seen so far ?
                // does this frame contain old data?
                // did we get new bytes
                if (ntohl(tcp->th_seq) < old_seq+old_len) {
                    uint i;
                    int seen = 0;
                    uint32_t seq_nr = ntohl(tcp->th_seq);
                    // check if we have seen this seq nr yet
                    for (i = 0; i < payload_ptr->seq_iterator && i < MAX_ARRAY; i++) {
                        if (payload_ptr->seq_array[i] == seq_nr) {
                            seen = 1;
                        }
                    }
                    // we have a dup -> check data
                    if (seen && ((ptr->state & STATE_ACKCHECK) == 0)) {
                        /* send ack and see if more data is coming */
                        uint8_t* data = NULL;
                        uint32_t this_len;

                        ringbuffer_lock(ring);

                        if ((this_len = ringbuffer_reserve(ring, &data, NULL)) == 0) {
                            log_error("initcwnd", "ring full sending ACK after retransmission");
                            ringbuffer_unlock(ring);
                            pthread_mutex_unlock(&ptr->state_lock);
                            return EXIT_FAILURE;
                        } else {
                            this_len = tcp_buildAck(packet, data, this_len);
                            struct ip* ip_hdrs = (struct ip*)&data[sizeof(struct ether_header)];
                            struct tcphdr* tcps = (struct tcphdr*)((char*)ip_hdrs + 4*ip_hdrs->ip_hl);
                            tcps->th_ack = htonl(payload_ptr->seq + payload_ptr->len_high_seq_pack);
                            tcps->th_win = htons(2*mss_buf[ptr->probe_num % mss_retries]);

                            tcps->th_sum = 0;
                            tcps->th_sum = tcp_checksum(sizeof(struct tcphdr), ip_hdrs->ip_src.s_addr, ip_hdrs->ip_dst.s_addr, tcps);
                            ip_hdrs->ip_sum = 0;
                            ip_hdrs->ip_sum = zmap_ip_checksum((unsigned short*)ip_hdrs);
                            ringbuffer_commit(ring, this_len);
                            ptr->state |= STATE_ACKCHECK;
                        }

                        ringbuffer_unlock(ring);
                    } else {
                        // packets did not arrive in order but the packet is no duplicate
                        
                        payload_ptr->bytes = payload_ptr->bytes + payload;
                        if (payload_ptr->seq_iterator < MAX_ARRAY) {
                            payload_ptr->seq_array[payload_ptr->seq_iterator] = ntohl(tcp->th_seq);
                            payload_ptr->seq_iterator++;
                        }
                        if (payload_ptr->seq_start > ntohl(tcp->th_seq)) {
                            payload_ptr->seq_start = ntohl(tcp->th_seq);
                        }
                        payload_ptr->packets = payload_ptr->packets + 1;
                        initcwnd_copy(packet, payload_ptr);
                    }
                } else if ((ptr->state & STATE_ACKCHECK) > 0) {
                    // after our ack, we received more data.
                    // that means that we hit the initcwnd with the first burst
                    fs_add_string(fs, "classification", (char*)"more data after ack (ok)", 0);
                    fs_add_uint64(fs, "success", 1);
                    fs_add_uint64(fs, "packets", payload_ptr->packets);
                    fs_add_uint64(fs, "payload", payload_ptr->bytes);

                    uint32_t total_length;
                    if (payload_ptr->seq_start > payload_ptr->seq) { // we overflowed
                        // total_length = payload_ptr->seq_start + ((uint32_t)0xFFFFFFFF - payload_ptr->seq);
                        // again, shouldn't this be:
                        total_length = payload_ptr->seq + ((uint32_t)0xFFFFFFFF - payload_ptr->seq_start) + 1;
                    } else {
                        total_length = payload_ptr->seq - payload_ptr->seq_start;
                    }

                    total_length += payload_ptr->len_high_seq_pack; // length of last packet

                    uint32_t mss = mss_buf[ptr->probe_num % mss_retries];

                    if (ptr->reported_mss == 1) {
                        fs_add_string(fs, "completed", (char*)"One chunk off", 0);
                    } else if (ptr->reported_mss > 1) {
                        fs_add_string(fs, "completed", (char*)"Multiple chunks off (notok)", 0);
                    } else if (ptr->estimated_mss != mss && payload_ptr->packets == 1) {
                        // if we only got a single packet that does not match our request's mss -> fail
                        fs_add_string(fs, "completed", (char*)"MSS error (only one, can't tell, notok)", 0);
                    } else if (ptr->estimated_mss != mss) {
                        // wrong MSS but we might still have enough data
                        if (total_length > ptr->estimated_mss * payload_ptr->packets) {
                            fs_add_string(fs, "completed", (char*)"Packet Loss error (ok?)", 0);
                        } else {
                            fs_add_string(fs, "completed", (char*)"MSS Error (ok)", 0);
                        }
                    } else {
                        // correct mss
                        if ((ptr->state & STATE_REDIRECT) > 0) {
                            fs_add_string(fs, "completed", (char*)"ok(redirected)", 0);
                        } else {
                            fs_add_string(fs, "completed", (char*)"ok", 0);
                        }
                    }

                    // init_cwnd is the number of bytes in total that we should have got divided by MSS
                    // some packets could have been dropped on their way
                    // last packet nevertheless contains highest seq num find lowest + highest and add length of last packet
                    // seq nums could loop

                    fs_add_uint64(fs, "seq_len", total_length);
                    fs_add_uint64(fs, "rep_mss", ptr->estimated_mss);
                    fs_add_uint64(fs, "probe_num", ptr->probe_num / mss_retries);
                    fs_add_uint64(fs, "req_mss", mss_buf[ptr->probe_num % mss_retries]);

                    if (ptr->estimated_mss == 0) {
                        fs_add_uint64(fs, "assumption", 0xFFFFFFFFFFFFFFFF);
                    } else {
                        double no_warn_buf;
                        fs_add_uint64(fs, "assumption", (uint64_t)(no_warn_buf = ceil(total_length / (double)ptr->estimated_mss)));
                    }

                    payload_ptr->buffer[BUFFERSIZE - 1] = '\0';
                    char* string_find = strstr(payload_ptr->buffer, "Server: AkamaiGHost");
                    if (string_find != NULL) {
                        fs_add_string(fs, "info", (char*)"AkamaiGHost", 0);
                    }

                    // send reset

                    uint8_t* data = NULL;
                    uint32_t this_len;

                    ringbuffer_lock(ring);

                    this_len = ringbuffer_reserve(ring, &data, NULL);
                    if (this_len == 0) {
                        log_error("initcwnd", "ring full sending RST after success");
                        ringbuffer_unlock(ring);
                        pthread_mutex_lock(&ptr->state_lock);
                        return EXIT_FAILURE;
                    } else {
                        this_len = tcp_buildRst(packet, data, this_len);
                        ringbuffer_commit(ring, this_len);
                    }

                    ringbuffer_unlock(ring);

                    pthread_mutex_unlock(&ptr->state_lock);

                    // remove from statemachine
                    pthread_mutex_lock(&statetable_lock);
                    remove_StateData(src_ip, ntohs(tcp->th_dport), myStateTable);
                    pthread_mutex_unlock(&statetable_lock);

                    return EXIT_SUCCESS;
                } else {
                    // Update our information on the connection
                    payload_ptr->bytes += payload;
                    payload_ptr->seq = ntohl(tcp->th_seq);
                    payload_ptr->len_high_seq_pack = payload;
                    if (ptr->estimated_mss != payload) {
                        // the packet size is changing... cannot tell anything
                        ptr->reported_mss += 1;
                    }

                    ptr->estimated_mss = MAX(ptr->estimated_mss, payload);
                    if (payload_ptr->seq_iterator < MAX_ARRAY) {
                        payload_ptr->seq_array[payload_ptr->seq_iterator] = ntohl(tcp->th_seq);
                        payload_ptr->seq_iterator++;
                    }

                    payload_ptr->packets += 1;
                    initcwnd_copy(packet, payload_ptr);
                }
                
                pthread_mutex_unlock(&ptr->state_lock);
            }
        }

        // connection should be closed
        if (tcp->th_flags & TH_FIN) {
            // we have not tried a redirection yet -> try it and return
            if (ptr->state == STATE_SYNACK || ((ptr->state & STATE_REDIRECT) > 0 && (ptr->state & STATE_LOCATION_LONG) == 0)) {
                if (redirect(packet, src_ip, ntohs(tcp->th_dport), ring) == EXIT_SUCCESS) {
                    return EXIT_FAILURE;
                }
            }
            
            // otherwise, or redirect failed -> save data
            fs_add_string(fs, "classification", (char*)"FIN DATA", 0);
            fs_add_uint64(fs, "success", 0);
            
            if (ptr->info != NULL && (ptr->state & STATE_LOCATION) == 0) {
                struct initcwnd_Data* payload_ptr = (struct initcwnd_Data*)ptr->info;
                fs_add_uint64(fs, "packets", payload_ptr->packets);
                fs_add_uint64(fs, "payload", payload_ptr->bytes);
                fs_add_string(fs, "completed", (char*)"?", 0);
                fs_add_uint64(fs, "assumption", payload_ptr->packets);
            } else {
                fs_add_uint64(fs, "packets", 0);
                fs_add_uint64(fs, "payload", 0);
                fs_add_string(fs, "completed", (char*)"", 0);
                fs_add_uint64(fs, "assumption", 0);
            }
            
            fs_add_uint64(fs, "probe_num", ptr->probe_num / mss_retries);
            fs_add_uint64(fs, "rep_mss", ptr->estimated_mss);
            fs_add_uint64(fs, "req_mss", mss_buf[ptr->probe_num % mss_retries]);
            
            uint8_t* data = NULL;
            uint32_t this_len;
            
            ringbuffer_lock(ring);
            
            if ((this_len = ringbuffer_reserve(ring, &data, &this_len)) == 0) {
                log_error("initcwnd", "ring full sending RST after FIN");
                ringbuffer_unlock(ring);
                return EXIT_FAILURE;
            } else {
                this_len = tcp_buildRst(packet, data, this_len);
                ringbuffer_commit(ring, this_len);
            }
            
            ringbuffer_unlock(ring);
            
            pthread_mutex_lock(&statetable_lock);
            remove_StateData(src_ip, ntohs(tcp->th_dport), myStateTable);
            pthread_mutex_unlock(&statetable_lock);
            return EXIT_SUCCESS;
        }

        return EXIT_FAILURE;
    }
}

void initcwnd_process_timeout(struct StateData* data)
{
    pthread_mutex_lock(&data->state_lock);
    if (data->state != STATE_ACKCHECK) {
        return;
    }

    struct initcwnd_Data* payload_ptr = (struct initcwnd_Data*)data->info;

    uint32_t total_length = 0; 
    if (payload_ptr->seq_start > payload_ptr->seq) {
        // total_length = payload_ptr->seq_start + ((uint32_t)0xFFFFFFFF - payload_ptr->seq);
        // again, what about
        total_length = payload_ptr->seq + ((uint32_t)0xFFFFFFFF - payload_ptr->seq_start) + 1;
    } else {
        total_length = payload_ptr->seq - payload_ptr->seq_start;
    }
    total_length += payload_ptr->len_high_seq_pack;
    
    fieldset_t* fs = fs_new_fieldset();
    
    fs_add_string(fs, "saddr", make_ip_str(data->ip), 1);
    fs_add_uint64(fs, "saddr_raw", (uint64_t)data->ip);
    fs_add_string(fs, "daddr", make_ip_str(0), 1);
    fs_add_uint64(fs, "daddr_raw", 0);
    fs_add_uint64(fs, "ipid", 0);
    fs_add_uint64(fs, "ttl", 255);
    
    fs_add_uint64(fs, "success", 1);
    fs_add_string(fs, "classification", (char*)"timeout waiting for new data", 0);
    fs_add_string(fs, "completed", (char*)"Not enough data? (notok)", 0);
    fs_add_uint64(fs, "seq_len", total_length);
    fs_add_uint64(fs, "rep_mss", data->estimated_mss);
    
    fs_add_uint64(fs, "probe_num", data->probe_num / mss_retries);
    fs_add_uint64(fs, "req_mss", mss_buf[data->probe_num % mss_retries]);
    
    if (data->estimated_mss == 0) {
        fs_add_uint64(fs, "assumption", 0xFFFFFFFFFFFFFFFF);
    } else {
        double no_warn_buf;
        fs_add_uint64(fs, "assumption", (uint64_t)(no_warn_buf = ceil(total_length/(double)data->estimated_mss)));
    }
    
    pthread_mutex_unlock(&data->state_lock);
    
    fs_add_system_fields(fs, 3, zsend.complete);
    
    fieldset_t* o = NULL;
    
    if (!evaluate_expression(zconf.filter.expression, fs)) {
        log_debug("initcwnd", "Filtered");
        goto cleanup;
    }
    
    o = translate_fieldset(fs, &zconf.fsconf.translation);
    if (zconf.output_module && zconf.output_module->process_ip) {
        pthread_mutex_lock(&recv_mutex);
        zconf.output_module->process_ip(o);
        pthread_mutex_unlock(&recv_mutex);
    }
cleanup:
    fs_free(fs);
    if (o) {
        free(o);
    }
}
