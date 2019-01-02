// @flow

import * as middy from "middy";
import { validate, JoiObject } from "joi";
import { indexOf } from "lodash";

export type IBodyConfig = {
  schema: JoiObject
};

export type IRequestValidatorConfig = {
  restrictedAccess: boolean,
  permittedSource: string[],
  body?: IBodyConfig
};

export const requestValidator = (
  config: IRequestValidatorConfig
): middy.IMiddyMiddlewareObject => {
  return {
    before: (handler, next) => {
      if (config.restrictedAccess && !handler.event.requestContext.authorizer) {
        console.error(handler.event);
        return handler.callback(null, {
          statusCode: 401
        });
      }

      if (config.permittedSource) {
        const source: string =
          handler.event.headers && handler.event.headers.Source
            ? handler.event.headers.Source
            : "app";
        let userGroups: any =
          handler.event.requestContext.authorizer.claims["cognito:groups"];

        if (userGroups === "admin") {
          userGroups = ["admin"];
        }

        if (indexOf(config.permittedSource, source) === -1) {
          console.error(source);
          return handler.callback(null, {
            statusCode: 403
          });
        }

        if (
          source === "backoffice" &&
          (!userGroups || (userGroups && indexOf(userGroups, "admin") === -1))
        ) {
          console.error(userGroups);
          console.error(source);
          return handler.callback(null, {
            statusCode: 403
          });
        }
      }

      if (config.body && config.body.schema) {
        if (!handler.event.body) {
          const message = "Body is required";
          console.error(message);
          return handler.callback(null, {
            statusCode: 400,
            body: JSON.stringify({ error: message })
          });
        }

        const validation = validate(handler.event.body, config.body.schema, {
          abortEarly: false
        });
        if (validation.error) {
          console.error(validation.error.message);
          return handler.callback(null, {
            statusCode: 400,
            body: JSON.stringify({ error: validation.error.message })
          });
        }
      }

      return next();
    }
  };
};
