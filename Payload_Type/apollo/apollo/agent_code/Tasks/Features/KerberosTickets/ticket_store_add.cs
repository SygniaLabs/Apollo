﻿#define COMMAND_NAME_UPPER

#if DEBUG
#define TICKET_STORE_ADD
#endif

#if TICKET_STORE_ADD

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using ApolloInterop.Classes;
using ApolloInterop.Features.KerberosTickets;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;

namespace Tasks;

public class ticket_store_add : Tasking
{
    
    [DataContract]
    internal struct TicketStoreAddParameters
    {
        [DataMember(Name = "base64ticket")]
        internal string base64Ticket;
    }

    public ticket_store_add(IAgent agent, MythicTask data) : base(agent, data)
    { }
    public override void Start()
    {
        MythicTaskResponse resp = new MythicTaskResponse { };
        try
        {
            TicketStoreAddParameters parameters = _jsonSerializer.Deserialize<TicketStoreAddParameters>(_data.Parameters);
            string base64Ticket = parameters.base64Ticket;
            byte[] ticketBytes = Convert.FromBase64String(base64Ticket);
            //make a placeholder ticket for now
            KerberosTicket? ticket = _agent.GetTicketManager().GetTicketDetailsFromKirbi(ticketBytes);
            if(ticket == null)
            {
                resp = CreateTaskResponse($"Failed to extract ticket from kirbi or failed to parse new data", true, "error");
            }
            else
            {
                _agent.GetTicketManager().AddTicketToTicketStore(new KerberosTicketStoreDTO(ticket));
                resp = CreateTaskResponse($"Added Ticket to Ticket Store", true);
            }
        }
        catch (Exception e)
        {
            resp = CreateTaskResponse($"Failed to add ticket into store: {e.Message}", true, "error");
        }
        //get and send back any artifacts
        IEnumerable<Artifact> artifacts = _agent.GetTicketManager().GetArtifacts();
        var artifactResp = CreateArtifactTaskResponse(artifacts);
        _agent.GetTaskManager().AddTaskResponseToQueue(artifactResp);
        
        _agent.GetTaskManager().AddTaskResponseToQueue(resp);
    }
}
#endif