import uuid
import json
import base64
import hashlib
import hmac
from datetime import datetime, timedelta
from enums import SimaPayloadType
from starlette.datastructures import UploadFile

from client import Client


class SimaSign:

    def __init__(self, sima_master_key, sima_client_id, sima_client_name, domain) -> None:
        self.master_key = sima_master_key
        self.client_id = sima_client_id
        self.client_name = sima_client_name
        self.domain = domain

    def sima_kyc_auth_payload(
        self,
        *,
        user_id: uuid.UUID,
        icon_uri: str,
        redirect_uri: str,
        web2app: bool = False,
    ):
        operation_id = str(uuid.uuid4())
        data_url = f"{self.domain}/getdata/{operation_id}/register?user_id={user_id}"
        callback_url = f"{self.domain}/callback/{operation_id}/register?user_id={user_id}"

        signable_container = self._generate_signable_container(
            operation_id=operation_id,
            type=SimaPayloadType.Auth,
            callback_url=callback_url,
            data_url=data_url,
            icon_uri=icon_uri,
            redirect_uri=redirect_uri,
        )
        payload = self._dump_sima_payload(signable_container)
        url = f"{self.domain}/?tsquery={payload}"
        client = Client(url=url)
        if web2app:
            return {
                "sima_sign_url": client.generate_url_or_qr(data={"url": f"sima://web-to-app?data={url}"}),
                "sima_operation_id": operation_id
            }
        
        qr_image = client.generate_url_or_qr(url)
        encoded_qr = base64.b64encode(qr_image)

        return {"sima_sign_url": encoded_qr, "sima_operation_id": operation_id}

    def get_created_time(self):
        utc_now = datetime.now().timestamp()
        return int(str(utc_now).split(".")[0])

    def get_expire_time(self):
        utc_now = (datetime.now() + timedelta(days=1)).timestamp()
        return int(str(utc_now).split(".")[0])
    
    def generate_hash_signature(self, signable_container: dict):
        data = json.dumps(signable_container).replace(" ", "")
        checksum = hashlib.sha256(data.encode()).digest()
        signature = hmac.new(
            key=self.master_key.encode(), msg=checksum, digestmod=hashlib.sha256
        ).digest()
        encoded_signature = base64.b64encode(signature).decode()
        return encoded_signature
    
    def _dump_sima_payload(self, signable_container):
        td = json.dumps(
            {
                "SignableContainer": signable_container,
                "Header": {
                    "AlgName": "HMACSHA256",
                    "Signature": self.generate_hash_signature(signable_container),
                },
            }
        ).replace(" ", "")
        payload = base64.b64encode(td.encode()).decode()
        return payload

    def _generate_signable_container(
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
                "NbfUTC": self.get_created_time(),
                "ExpUTC": self.get_expire_time(),
                "Assignee": [],
            },
            "DataInfo": {
                "DataURI": data_url  # f"https://df5b-213-154-0-254.ngrok-free.app/getdata/{operation_id}/{data.value}"
            },
            "ClientInfo": {
                "ClientId": self.client_id,
                "ClientName": self.client_name,
                "IconURI": icon_uri,
                "Callback": callback_url,  # f"https://df5b-213-154-0-254.ngrok-free.app/callback/{loan_request_id}",
                "RedirectURI": redirect_uri,
            },
        }

    def generate_sima_sign_contract(
        self,
        *,
        request_id: str,
        identity_id: uuid.UUID,
        user_fin: str,
        token: str,
        web2app: bool = False,
    ):
        operation_id = str(uuid.uuid4())

        data_url = f"{self.domain}/getdata/{operation_id}/sign/{identity_id}/{request_id}"
        callback_url = f"{self.domain}/callback/{operation_id}/sign/{identity_id}/{request_id}?token={token}"
        signable_container = self._generate_signable_container(
            operation_id, SimaPayloadType.Sign, callback_url, data_url, self.icon_uri, self.redirect_uri
        )
        signable_container["OperationInfo"]["Assignee"].append(user_fin)
        payload = self._dump_sima_payload(signable_container)
        url = f"{self.domain}/?tsquery={payload}"
        client = Client(url=url)
        if web2app:
            return {
                "sima_sign_url": client.generate_url_or_qr(data={"url": f"sima://web-to-app?data={url}"}),
                "sima_operation_id": operation_id
            }
        
        qr_image = client.generate_url_or_qr(url)
        encoded_qr = base64.b64encode(qr_image)

        return {"sima_sign_url": encoded_qr, "sima_operation_id": operation_id}

            


