import uuid
import json
import base64
import hashlib
import hmac
from typing import Union
from datetime import datetime, timedelta
from sima_sign.enums import SimaPayloadType
from sima_sign.client import Client


class SimaSign:

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
        data = json.dumps(signable_container).replace(" ", "")
        checksum = hashlib.sha256(data.encode()).digest()
        signature = hmac.new(
            key=self.__master_key.encode(), msg=checksum, digestmod=hashlib.sha256
        ).digest()
        encoded_signature = base64.b64encode(signature).decode()
        return encoded_signature
    
    async def __create_operation_id(self):
        return str(uuid.uuid4())

    async def __dump_sima_payload(self, signable_container):
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
        client = Client(url=url)
        if web2app:
            return {
                "sima_sign_url": await client.generate_url_or_qr(
                    data={"url": f"sima://web-to-app?data={url}"}
                ),
                "sima_operation_id": operation_id,
            }

        qr_image = await client.generate_url_or_qr(url)
        encoded_qr = base64.b64encode(qr_image)

        return {"sima_sign_url": encoded_qr, "sima_operation_id": operation_id}

    async def generate_sima_sign_contract(
        self,
        *,
        request_id: str,
        identity_id: Union[str, uuid.UUID, int],
        fin_code: str,
        token: str,
        web2app: bool = False,
    ):
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
        client = Client(url=url)
        if web2app:
            return {
                "sima_sign_url": await client.generate_url_or_qr(
                    data={"url": f"sima://web-to-app?data={url}"}
                ),
                "sima_operation_id": operation_id,
            }

        qr_image = await client.generate_url_or_qr(url)
        encoded_qr = base64.b64encode(qr_image)

        return {"sima_sign_url": encoded_qr, "sima_operation_id": operation_id}
