/**
*******************************************************************************
*
* @file arp.c
*
* @brief Implementation of RFC 826: Address Resolution Protocol (ARP)
* @author Mindspeed Technologies
*
* COPYRIGHT&copy; 2010 Mindspeed Technologies.
* ALL RIGHTS RESERVED
*
* This is Unpublished Proprietary Source Code of Mindspeed Technologies
*
******************************************************************************/


#include "global.h"
#include "scmgr.h"
#include "ethernet.h"
#include "aal5.h"
#include "utillib.h"	// for swap16

BOOL gServerAdd;
extern BOOL gMiroStandingBy;
extern PEthernetContext gPEthernetContext[2];

extern PIPv4Context gPIPV4Context;

static PEthernetContext gPMyEthContext;
static U8 ether_broadcast_addr[ETHER_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

extern PIPv6Context gPIPV6Context;
/****************************************************************************************
 *
 * Function:        ARP_Set_Service_Config
 * Parameter(s):    p - pointer to config data
 *					Length - length in bytes
 * Return value:    Length
 *
 * Description:     This routing handles ARP_SERVICE_CONFIG API call.
 *
 ****************************************************************************************/
U16 ARP_HandleARP_SERVICE_CFG(U16 *p, U16 Length)
{
	U16 ARP_Parameter;
	U16 Cmd[4];
	U32 *pAddress;

	pAddress= gPIPV6Context->ip_addr;

	if(ISMASTERCONFIG())
		return CMDDAT_CNF_ERROR_ARP_CHAGALL;

	// Check Length
	if  (Length != 2)
		return CMDDAT_CNF_ERROR_ARP_MSG_LEN;
	// Check that Ethernet layer exists
	if (gPEthernetContext[gEMACSelected] == NULL)
		return CMDDAT_CNF_ERROR_ARP_NO_ETH_LAYER;
	
	// Local Ethernetcontext pointer
	gPMyEthContext = gPEthernetContext[gEMACSelected];

	// Get ARP Service Config Parameter
	SFL_memcpy (&ARP_Parameter, (U8 *)p, 2);

	// May check value
	gPMyEthContext->ARP_SERVICE_CONFIG = ARP_Parameter;
	// Always allow Multicast Frames into the MAC Layer
		if ((gPIPV6Context != NULL)&&(IS_IPV6_ZERO(pAddress) != 0)&&(!Is_EMAC_PromiscuousMode(gEMACSelected)))
		{
			// Enable ICMPv6 Multi-cast Frame Processing
			// Enable the ICMP Neighbor Discovery Multicast MAC Address
			// if the ARP service configuration has enable the ARP reply
			// and not a Chagall Master
			SFL_memcpy(&Cmd[2],&gPIPV6Context->ip_addr[3],4); // Overwrite byte 2 later
			Cmd[0]= 0x0;  // Add Multicast Address
			Cmd[1]= 0x3333;
			Cmd[2] |= 0x00ff;
			Ethernet_HandleIPv6_InternalSET_MULTICAST_ETH_ADDR(Cmd, 8);	
		}
	return CMDDAT_CNF_OK;
}


/****************************************************************************************
 *
 * Function:        ARP_QueryARP_SERVICE_CFG
 * Parameter(s):    p - pointer to config data
 *					Length - length in bytes
 * Return value:    Length
 *
 * Description:     This routing handles ARP_SERVICE_CONFIG API call.
 *
 ****************************************************************************************/
 U8 ARP_QueryARP_SERVICE_CFG(U16 * Payload)
{
	U8 Length = 0;
 	
	if ( gPEthernetContext[gEMACSelected]!= NULL )
	{
		SFL_memcpy(Payload, &gPEthernetContext[gEMACSelected]->ARP_SERVICE_CONFIG, sizeof(gPEthernetContext[gEMACSelected]->ARP_SERVICE_CONFIG));
		Length = sizeof(gPEthernetContext[gEMACSelected]->ARP_SERVICE_CONFIG);
	}
	return Length;
}



/****************************************************************************************
 *
 * Function:        ARP_HandleSET_IP_ADDR_LIST
 * Parameter(s):    p - pointer to config data
 *				Length - length in bytes
 * Return value:    error code
 *
 * Description:     This routing handles SET_IP_ADDR_LIST API call.
 *
 ****************************************************************************************/
U16 ARP_HandleSET_IP_ADDR_LIST(U16 *p, U16 Length)
{
	int i, j;
	U32 IPSaddr;

	// Check IP layer exists
	if (gPIPV4Context == NULL)
       	return CMDDAT_CNF_ERROR_IP_ADDRESS_NO_IP_LAYER;

	// Check length is a multiple of 4 and doesn't exceed the number of IP address
	if  ( ((Length & 0x0003) != 0) ||  (Length > (4*NUM_IP_SADDR)) )
		return CMDDAT_CNF_ERROR_ARP_MSG_LEN;

	// Check none of the passed address is set to 0
	for( i = 0; i < (Length/2); i+=2)
	{
		IPSaddr = (p[i] + (p[i+1] << 16));
		if (IPSaddr == 0)
			return CMDDAT_CNF_ERROR_IP_ADDRESS_BAD_IP_ADDRESS;
	}

	// Update table with parameters
	for( i = 0 , j = 0; i < (Length/2); i+=2, j++)
	{
		IPSaddr = (p[i] + (p[i+1] << 16));
		gPIPV4Context->ARP_List_Saddr[j] = IPSaddr;
	}

	// Complete the table with 0
	for ( ; j < NUM_IP_SADDR ; j++ )
	{
		gPIPV4Context->ARP_List_Saddr[j] = 0;
	}
	
	return CMDDAT_CNF_OK;
}


/****************************************************************************************
 *
 * Function:        ARP_QuerySET_IP_ADDR_LIST
 * Parameter(s):   Payload - pointer data
 *
 * Return value:    Length
 *
 * Description:     This routing handles SET_IP_ADDR_LIST API query.
 *
 ****************************************************************************************/
 U8 ARP_QuerySET_IP_ADDR_LIST(U16 * Payload)
 {
	 U8 Length = 0;
	 int i;

	if ( gPIPV4Context!= NULL )
	{
		for( i = 0 ; i < NUM_IP_SADDR; i++)
		{// Look in the ARP IP Source Address table
			if ( gPIPV4Context->ARP_List_Saddr[i] != 0 )
			{// Put all IP addresses different from 0
				SFL_memcpy(Payload, &gPIPV4Context->ARP_List_Saddr[i] , sizeof(U32));
				Length += sizeof(U32);
				Payload += (sizeof(U32) >> 1);
			}
			else
				break;
		}
	}
	return Length;
 }


/****************************************************************************************
 *
 * Function:        ARP_LayerStatisticResponse
 * Parameter(s):    Payload - pointer to response data
 *					ResetStat - 1: reset stat after read
 * Return value:    Length of statistic in bytes
 *
 * Description:     This function returns statistic info for ARP layer.
 *
 ****************************************************************************************/
U8 ARP_LayerStatisticResponse (U16 *Payload, U16 ResetStat)
{
	U8 Length = sizeof (ARPStat);
	U8 Length1 = 0;
	U16 *ptr;
	U32 * pPayload = (U32 *)Payload;

	*pPayload++ = ARP_LAYERSTATISTIC_REV;

	// Put Statistics
	if (gPEthernetContext[gEMACSelected] != NULL )
		SFL_memcpy(pPayload, &gPEthernetContext[gEMACSelected]->ArpStat, Length);
	else // No Ethernet context yet, return 0
		memset(pPayload, 0, Length);

	if (gPIPV6Context != NULL)
	{
		Length1= sizeof(NdStat);
		ptr = (U16 *)pPayload + (Length/2);
		SFL_memcpy(ptr,&gPIPV6Context->NDStats,Length1);
		Length += Length1;
	}

	// Reset statistics
	if (ResetStat)
	{
		memset(&gPEthernetContext[gEMACSelected]->ArpStat, 0, Length);

		if (Length1)
			memset(&gPIPV6Context->NDStats, 0, Length1);
	}

	return (Length+4);
}

/****************************************************************************************
 *
 * Function:        ARP_SendFrame
 * Parameter(s):    PFDesc - frame descriptor
 * Return value:    None
 *
 * Description:     Called to send outgoing ARP packets
 *
 ****************************************************************************************/
static void ARP_SendFrame (PFDesc ThisFdesc, HANDLE hSrcDesc)
{
	U32 FromPort = ThisFdesc->Timestamp; // The port, we've received ARP request on
	U8 BDescIndex = gPEthernetContext[FromPort]->BDescIndex; // Both ports may be active

	// Update Tx statistics
	gPEthernetContext[FromPort]->ArpStat.Eth_ARP_Tx++;

	// The Rx Frames has been updated (ARP data)
	// Just need to use Received Src MAC as destination and our MAC as source 
	ThisFdesc->Length = sizeof (struct ether_arp) + ThisFdesc->Offset - ETH_ALLOCATION_OFFSET;
	if (BDescIndex == 0)
		ThisFdesc->BDesc[BDescIndex].BControl = ThisFdesc->Length | IDMA_BCONTROL_BLAST;
	else // oPOS or oAAL5
		ThisFdesc->BDesc[BDescIndex].BControl = ThisFdesc->Length;

	ThisFdesc->BDesc[BDescIndex ].BPtr = safePointer	(ThisFdesc->Payload, 
						ETH_ALLOCATION_OFFSET);
	ThisFdesc->FControl = IDMA_FCONTROL_FREADY;

	ThisFdesc->FrameType = PROTID_ARP; 
	Ethernet_SendFrame_ReverseMAC(ThisFdesc, ETH_ALLOCATION_OFFSET, hSrcDesc);
}

/****************************************************************************************
 *
 * Function:        ARP_Dispatch
 * Parameter(s):    PFDesc - frame descriptor
 * Return value:    BOOL - TRUE if no ERROR, else FALSE
 *
 * Description:     Called to process incoming ARP packets
 *
 ****************************************************************************************/
BOOL ARP_Dispatch (PFDesc ThisFdesc, HANDLE hSrcDesc)
{
	struct ether_arp ea;
	U32 sizeof_enet_addr;
	U32 my_ip_addr = pDevicedesc->ip_addr;
	U32 isaddr, itaddr=0;
	U32 FromPort = ThisFdesc->Timestamp; // The port, we've received ARP request on
	PEthernetContext PEthContext = gPEthernetContext[FromPort]; // Both ports may be active
	U8 *my_hw_addr = PEthContext->enet_addr; 
	U32 op;
	
	int ec = FALSE;
	
	// Update ARP statistics
	PEthContext->ArpStat.Eth_ARP_Rx++;

	// Get ARP packet
	SFL_memcpy (&ea, ThisFdesc->Payload + ThisFdesc->Offset, sizeof (struct ether_arp));

	// Check type first (we just need to check requests)
	op = swap16(ea.arp_op);
	
	sizeof_enet_addr = sizeof (ea.arp_sha);	

	if ((op == ARPOP_REQUEST) && 
	    (PEthContext->ARP_SERVICE_CONFIG & ARP_SERVICE_CFG_REPLIES_MASK))
	{
		// This is an ARP Request and we need to process it
		if (gMiroStandingBy == TRUE)
		{
			// TODO: This seems a little heavy-handed.
			ThisFdesc->Next = NULL;
			PEthContext->TrashPkt(ThisFdesc);
			return ec;
		}

		// Only process frames with correct length and type
		else if (ThisFdesc->Length >= sizeof (struct arphdr) &&
			swap16(ea.arp_hrd) == ARPHDR_ETHER &&
			ThisFdesc->Length >= sizeof (struct arphdr) + 2*ea.arp_hln + 2*ea.arp_pln)
		{// Process ARP frame...
			// Can only handle IPv4 address
			if (swap16(ea.arp_pro) != ETHERTYPE_IP || ea.arp_pln != 4)
				goto out;
			
			op = swap16(ea.arp_op);
			SFL_memcpy (&itaddr, ea.arp_tpa, sizeof (itaddr));
			SFL_memcpy (&isaddr, ea.arp_spa, sizeof (isaddr));

#ifdef AAL5_SUPPORTED
			if (hSrcDesc)	// Comes from AAL5
			{
				if (ATMARP_FindSvcDescByIP(isaddr, hSrcDesc))
					goto reply;
			}
#endif
			if (my_ip_addr != 0)
			{// One source IP address set with SET_IP_ADDRESS
				// Drop if sender & target IP address does not match ours
				if (isaddr != my_ip_addr && itaddr != my_ip_addr)
					goto out;
			}
			else
			{// Multiple Source IP address mode
				int i;
				
				for(i=0;i<NUM_IP_SADDR;i++)
				{//Search the address in the list of Source Address
					my_ip_addr = gPIPV4Context->ARP_List_Saddr[i];
					if (isaddr == my_ip_addr || itaddr == my_ip_addr)
						break;
				}
				// IP address not found in the table
				if ( i == NUM_IP_SADDR)
					goto out;
			}

			// Sender hw addr is same as my hardware address, discard
			if (!memcmp (ea.arp_sha, my_hw_addr, sizeof_enet_addr))
				goto out;

			// Sender hardware address is a broadcast address
			if (!memcmp (ea.arp_sha, ether_broadcast_addr, sizeof_enet_addr))
				goto out;

			// Sender IP address is same as ours, duplicate IP address
			//if (isaddr == my_ip_addr)
			//{
			//	// Need to keep a count here for duplicate IP addr
			//	goto reply;
			//}
			// Perform ARP lookup here, if we were to maintain an ARP cache
			//      - table lookup, create new entries or do updates here...
			// ARP_lookup (...);
			ec = TRUE;
		}
	reply:
		if (op != ARPOP_REQUEST)
		{// This is an ARP reply
			// Update ARP statistics
			PEthContext->ArpStat.Eth_ARP_Response_Rx++;
		out:
			ThisFdesc->Next = NULL;
			PEthContext->TrashPkt(ThisFdesc);

			// Keep count of # of drop ARP packets here (todo)
			PEthContext->ArpStat.Eth_ARP_Frames_Dropped++;
			return ec;
		}
		
		// Update ARP statistics
		PEthContext->ArpStat.Eth_ARP_Request_Rx++;
		
		// If target IP address matches one of ours
		// In case of MIPSA, my_ip_addr is set to the proper IP address
		if (itaddr == my_ip_addr)
		{// Start building ARP reply
			SFL_memcpy (ea.arp_tha, ea.arp_sha, sizeof_enet_addr);
			SFL_memcpy (ea.arp_sha, my_hw_addr, sizeof_enet_addr);
			SFL_memcpy (ea.arp_tpa, ea.arp_spa, sizeof (ea.arp_spa));
			SFL_memcpy (ea.arp_spa, &my_ip_addr, sizeof (ea.arp_spa));
			ea.arp_op = swap16(ARPOP_REPLY);
			ea.arp_pro = swap16(ETHERTYPE_IP);

			SFL_memcpy (ThisFdesc->Payload + ThisFdesc->Offset, 
						&ea, 
						sizeof (struct ether_arp));

			// Send ARP packet	
			ARP_SendFrame (ThisFdesc, hSrcDesc);
		}
		else
		{// To ensure it's not possible to leave ARP_Dispatch withouth freeing Fdesc
			ThisFdesc->Next = NULL;
			PEthContext->TrashPkt(ThisFdesc);

			// Keep count of # of drop ARP packets here (todo)
			PEthContext->ArpStat.Eth_ARP_Frames_Dropped++;
			return ec;
		}
	}
	else if (PEthContext->ETH_SPECIALPKT_HANDLING_SERVICE_CONFIG & SPECIALPKT_HANDLING_ETH_ARP_MASK)
	{// Host wants ARP packets
		if (  ( (op == ARPOP_REQUEST) &&  (!(PEthContext->ETH_SPECIALPKT_HANDLING_SERVICE_CONFIG & SPECIALPKT_HANDLING_ETH_ARPREQ_MASK)))
			|| (op == ARPOP_REPLY) )
		{// ARP reply or request with request enabled
			Ethernet_SpecialPacket_Forward(ThisFdesc);
			ec = TRUE;
		}
		else
		{// ARP request whe request forwarding not enabled
			PEthContext->TrashPkt(ThisFdesc);

			// Keep count of # of drop ARP packets here
			PEthContext->ArpStat.Eth_ARP_Frames_Dropped++;
		}
	}
	else
	{// Case of ARP_Reply when forward is not enabled -> drop
		PEthContext->TrashPkt(ThisFdesc);

		// Keep count of # of drop ARP packets here
		PEthContext->ArpStat.Eth_ARP_Frames_Dropped++;
	}
	return ec;
}

