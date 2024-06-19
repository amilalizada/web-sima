import uuid
import json
import base64
import hashlib
import hmac
from typing import Union
from datetime import datetime, timedelta
from web_sima.enums import SimaPayloadType


class SimaClient:

    def __init__(
        self, sima_master_key, sima_client_id, sima_client_name, base_api_url
    ) -> None:
        self.__master_key = sima_master_key
        self.__client_id = sima_client_id
        self.__client_name = sima_client_name
        self.__base_api_url = base_api_url

    async def __get_created_time(self):
        utc_now = datetime.now().timestamp()
        return int(str(utc_now).split(".")[0])

    async def __get_expire_time(self):
        utc_now = (datetime.now() + timedelta(days=1)).timestamp()
        return int(str(utc_now).split(".")[0])

    async def __generate_hash_signature(self, signable_container: dict):
        """
        Generates a hash signature for the given signable container.

        Parameters:
            signable_container (dict): The container to generate the hash signature for.

        Returns:
            str: The encoded signature as a base64 string.
        """
        data = json.dumps(signable_container).replace(" ", "")
        checksum = hashlib.sha256(data.encode()).digest()
        signature = hmac.new(
            key=self.__master_key.encode(), msg=checksum, digestmod=hashlib.sha256
        ).digest()
        encoded_signature = base64.b64encode(signature).decode()
        return encoded_signature
    
    async def __create_operation_id(self):
        """
        Generates a unique operation ID.

        Returns:
            str: The generated operation ID.
        """
        return str(uuid.uuid4())

    async def __dump_sima_payload(self, signable_container):
        """
        Generates the Sima payload by encoding the given signable container into a JSON string and then base64 encoding it.

        Args:
            signable_container (dict): The container to generate the payload for.

        Returns:
            str: The encoded payload as a base64 string.
        """
        td = json.dumps(
            {
                "SignableContainer": signable_container,
                "Header": {
                    "AlgName": "HMACSHA256",
                    "Signature": await self.__generate_hash_signature(signable_container),
                },
            }
        ).replace(" ", "")
        payload = base64.b64encode(td.encode()).decode()
        return payload

    async def __generate_signable_container(
        self,
        *,
        operation_id: str,
        type: SimaPayloadType,
        callback_url: str,
        data_url: str,
        icon_uri: str,
        redirect_uri: str,
    ) -> dict:
        """
        Generates a signable container with detailed information including ProtoInfo, OperationInfo, DataInfo, and ClientInfo.

        Parameters:
            operation_id (str): The unique identifier for the operation.
            type (SimaPayloadType): The type of payload.
            callback_url (str): The URL to call back.
            data_url (str): The URL containing data information.
            icon_uri (str): The URI for the icon.
            redirect_uri (str): The URI to redirect to.

        Returns:
            dict: A dictionary containing the signable container information.
        """
        return {
            "ProtoInfo": {"Name": "web2app", "Version": "1.3"},
            "OperationInfo": {
                "Type": type,
                "OperationId": operation_id,
                "NbfUTC": await self.__get_created_time(),
                "ExpUTC": await self.__get_expire_time(),
                "Assignee": [],
            },
            "DataInfo": {"DataURI": data_url},
            "ClientInfo": {
                "ClientId": self.__client_id,
                "ClientName": self.__client_name,
                "IconURI": icon_uri,
                "Callback": callback_url,
                "RedirectURI": redirect_uri,
            },
        }

    async def sima_kyc_auth_payload(
        self,
        *,
        identity_id: Union[str, uuid.UUID, int],
        icon_uri: str,
        redirect_uri: str,
        web2app: bool = False,
    ):
        """
        Generates the payload for Sima KYC authentication.

        Args:
            identity_id (Union[str, uuid.UUID, int]): The identity ID of the user.
            icon_uri (str): The URI for the icon.
            redirect_uri (str): The URI to redirect to.
            web2app (bool, optional): Whether to generate a sign URL for web-to-app integration. Defaults to False.

        Returns:
            dict: A dictionary containing the Sima sign URL and the operation ID.
                - If `web2app` is True:
                    - "sima_sign_url" (str): The sign URL for web-to-app integration.
                    - "sima_operation_id" (str): The operation ID.
                - Otherwise:
                    - "sima_sign_url" (str): The encoded QR image as a base64 string.
                    - "sima_operation_id" (str): The operation ID.

        """
        operation_id = await self.__create_operation_id()
        data_url = f"{self.__base_api_url}/getdata/{operation_id}/register?user_id={identity_id}"
        callback_url = f"{self.__base_api_url}/callback/{operation_id}/register?user_id={identity_id}"

        signable_container = await self.__generate_signable_container(
            operation_id=operation_id,
            type=SimaPayloadType.Auth,
            callback_url=callback_url,
            data_url=data_url,
            icon_uri=icon_uri,
            redirect_uri=redirect_uri,
        )
        payload = await self.__dump_sima_payload(signable_container)
        url = f"{self.__base_api_url}/?tsquery={payload}"
        response = {
            "url": url,
            "sima_operation_id": operation_id,
        }
        if web2app:
            response["url"] = f"sima://web-to-app?data={url}"

        return response

    async def generate_sima_sign_contract(
        self,
        *,
        request_id: str,
        identity_id: Union[str, uuid.UUID, int],
        fin_code: str,
        token: str,
        web2app: bool = False,
    ):
        """
        Generates and returns the Sima sign contract based on the provided request details.
        Parameters:
            request_id (str): The ID of the request.
            identity_id (Union[str, uuid.UUID, int]): The identity ID of the user.
            fin_code (str): The FIN code.
            token (str): The token for authentication.
            web2app (bool, optional): Whether to generate a sign URL for web-to-app integration. Defaults to False.
        Returns:
            dict: A dictionary containing the Sima sign URL and the operation ID.
                - If `web2app` is True:
                    - "sima_sign_url" (str): The sign URL for web-to-app integration.
                    - "sima_operation_id" (str): The operation ID.
                - Otherwise:
                    - "sima_sign_url" (str): The encoded QR image as a base64 string.
                    - "sima_operation_id" (str): The operation ID.
        """
        
        operation_id = await self.__create_operation_id()

        data_url = f"{self.__base_api_url}/getdata/{operation_id}/sign/{identity_id}/{request_id}"
        callback_url = f"{self.__base_api_url}/callback/{operation_id}/sign/{identity_id}/{request_id}?token={token}"
        signable_container = await self.__generate_signable_container(
            operation_id,
            SimaPayloadType.Sign,
            callback_url,
            data_url,
            self.icon_uri,
            self.redirect_uri,
        )
        signable_container["OperationInfo"]["Assignee"].append(fin_code)
        payload = await self.__dump_sima_payload(signable_container)
        url = f"{self.__base_api_url}/?tsquery={payload}"
        response = {
            "url": url,
            "sima_operation_id": operation_id,
        }
        if web2app:
            response["url"] = f"sima://web-to-app?data={url}"
            
        return response
