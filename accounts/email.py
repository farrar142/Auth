from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .tasks import EmailLoginNecessaries


def get_email_login_html(data: "EmailLoginNecessaries", code: str, date: datetime):
    url = f"{data['callback']}?scheme={data['scheme']}&url={data['url']}&code={code}"
    return f"""<table
    cellpadding="0" cellspacing="0" border="0" width:"100%"
    role="presentation"
    style="border-collapse:collapse!important;"
    >
    <tbody>
        <tr>
            <td align="center> valign="top" style="border-collapse:collapse!important;padding-top:10px">
                <table 

                cellpadding="0" cellspacing="0" border="0" width="100%"
                role="presentation"
                    style="border-collapse:collapse!important;"
                >  
                    <tbody>
                        <tr>
                            <td align="center" valign="top" style="border-collapse:collapse!important;padding:10px 0;border-radius:3px;
                            padding:10px 30px">
                                <h2>블로그 서비스 이용을 환영합니다!!</h2>
                                <h3>이메일 계정 인증을 완료해 주세요.</h3>
                                <p>* 해당 인증 메일은 1시간동안 유효하며, 이후엔 재발송 바랍니다.</p>
                                <p>* 한번 사용된 인증 메일은 재사용 불가합니다.</p>
                                <a href="{url}"
                                        style="
                                            cursor: pointer;
                                            width: 312px;
                                            border-radius: 10px;
                                            border-width: 0px;
                                            text-decoration:none;
                                        ">
                                        <h5 style="padding: 15px 4px 15px 4px; text-align: center;
                                        width:50%;
                                            border-radius: 10px;
                                            color:#000;
                                            background: linear-gradient(
                                                    90deg,
                                                    rgba(32, 254, 221, 0.2) 0%,
                                                    rgba(154, 246, 158, 0.2) 68.88%
                                                ),
                                                #20fedd;">
                                            이메일 인증하기
                                        </h5>
                                    </a>
                                <p>{date.year}.{date.month}.{date.day} SENT</p>     
                            </td>
                        </tr>
                    </tbody>
                </table>
            </td>
        </tr>
        </tbody>
    </table>
    """
