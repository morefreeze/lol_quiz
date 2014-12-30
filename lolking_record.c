#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  /* GIMME a libpcap plz! */
#include <errno.h>

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main(int argc, char **argv)
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Retrieve the device list */
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    inum = 2;
    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

    /* Open the device */
    /* Open the adapter */
    if ((adhandle= pcap_open_live(d->name,	// name of the device
                    65536,			// portion of the packet to capture. 
                    // 65536 grants that the whole packet will be captured on all the MACs.
                    1,				// promiscuous mode (nonzero means promiscuous)
                    1000,			// read timeout
                    errbuf			// error buffer
                    )) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    /*
       pcap_t *fp;
       if ((fp = pcap_open_offline("lolking0.pcap",			// name of the device
       errbuf					// error buffer
       )) == NULL)
       {
       fprintf(stderr,"\nUnable to open the file %s.\n", argv[1]);
       return -1;
       }

       pcap_loop(fp, 0, packet_handler, NULL);

       pcap_close(fp);
       */

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, NULL);

    pcap_close(adhandle);

    system("pause");
    return 42;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    /*
     * unused parameters
     */
    (VOID)(param);
    (VOID)(pkt_data);

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    //printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
    int ignore_len = 14 + 20 + 20;
    if (header->len <= ignore_len)
        return ;
    const u_char *wb_data = pkt_data+ignore_len;
    u_char is_wb = wb_data[0];
    if (0x81 != is_wb)
        return ;
    int wb_len = wb_data[1];
    if (0x7e == wb_len){
        wb_len = ((int)wb_data[2] << 8) | (int)wb_data[3];
        // shift 2B for len byte
        wb_data = wb_data+2;
    }
    if ('{' != wb_data[2])
        return ;
    if (0 == strncmp("{\"gameId", (char*)(wb_data+2), strlen("{\"gameId"))
            || 0 == strncmp("{\"questionAnswerWrap", (char*)(wb_data+2), strlen("{\"questionAnswerWrap"))
       ){
        FILE *out_fp = fopen("lolking0.out", "ab");
        fwrite(wb_data+2, sizeof(u_char), wb_len, out_fp);
        fwrite("\n", sizeof(u_char), 1, out_fp);
        fclose(out_fp);
    }

}
