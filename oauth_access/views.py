from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext

from oauth_access.access import OAuthAccess, OAuth20Token
from oauth_access.exceptions import MissingToken


def oauth_login(request, service, redirect_field_name="next", redirect_to_session_key="redirect_to"):
    access = OAuthAccess(service)
    if not service == "facebook":
        token = access.unauthorized_token()
        request.session["%s_unauth_token" % service] = token.to_string()
    else:
        token = None
    if hasattr(request, "session"):
        request.session[redirect_to_session_key] = request.GET.get(redirect_field_name)
    return HttpResponseRedirect(access.authorization_url(token))


def oauth_callback(request, service):
    ctx = RequestContext(request)
    access = OAuthAccess(service)

    access_token = request.GET.get('access_token', None)
    signed_request = request.GET.get('signed_request', None)
    if access_token and signed_request:
        data = access.parse_signed_request(signed_request)
        if data:
            auth_token = OAuth20Token(access_token)
            return access.callback(request, access, auth_token)
        else:
            return render_to_response("oauth_access/oauth_error.html")

    unauth_token = request.session.get("%s_unauth_token" % service, None)
    try:
        auth_token = access.check_token(unauth_token, request.GET)
    except MissingToken:
        ctx.update({"error": "token_missing"})
    else:
        if auth_token:
            return access.callback(request, access, auth_token)
        else:
            # @@@ not nice for OAuth 2
            ctx.update({"error": request.GET.get("error", "token_mismatch")})
    return render_to_response("oauth_access/oauth_error.html", ctx)


def finish_signup(request, service):
    access = OAuthAccess(service)
    return access.callback.finish_signup(request, service)
