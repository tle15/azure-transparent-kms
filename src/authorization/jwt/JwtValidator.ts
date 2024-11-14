// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as ccfapp from "@microsoft/ccf-app";
import { ServiceResult } from "../../utils/ServiceResult";
import { IValidatorService } from "../IValidationService";
import { IJwtIdentityProvider } from "./IJwtIdentityProvider";
import { MsJwtProvider } from "./MsJwtProvider";
import { Logger, LogContext } from "../../utils/Logger";

export class JwtValidator implements IValidatorService {
  private readonly identityProviders: IJwtIdentityProvider;
  private logContext: LogContext;

  constructor(logContext?: LogContext) {
    this.logContext = (logContext?.clone() || new LogContext()).appendScope("JwtValidator");
    this.identityProviders = new MsJwtProvider("JwtProvider", this.logContext);
    Logger.debug("Set default JWT provider", this.logContext);
  }

  validate(request: ccfapp.Request<any>): ServiceResult<string> {
    const jwtCaller = request.caller as unknown as ccfapp.JwtAuthnIdentity;
    Logger.info(
      `JWT jwtCaller (JwtValidator)-> ${jwtCaller.jwt.keyIssuer}`,
      this.logContext
    );
    Logger.info(`JWT content: ${JSON.stringify(jwtCaller.jwt)}`, this.logContext);

    const isValidJwtToken = this.identityProviders.isValidJwtToken(jwtCaller);
    Logger.info(
      `JWT validation result (JwtValidator) for provider ${this.identityProviders.name}-> ${JSON.stringify(isValidJwtToken)}`,
      this.logContext
    );
    return isValidJwtToken;
  }
}
