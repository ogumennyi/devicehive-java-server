package com.devicehive.base;

import com.devicehive.shim.api.Body;
import com.devicehive.shim.api.Request;
import com.devicehive.shim.api.Response;
import com.devicehive.shim.api.server.RequestHandler;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Profile("test")
@Component
public class RequestDispatcherProxy implements RequestHandler {

    private RequestHandler requestHandler;

    @Override
    public Response handle(Request request) {
        if (requestHandler == null) {
            return Response.newBuilder()
                    .withBody(new Body("") {
                    })
                    .buildSuccess();
        } else {
            return requestHandler.handle(request);
        }
    }

    public void setRequestHandler(RequestHandler requestHandler) {
        this.requestHandler = requestHandler;
    }
}