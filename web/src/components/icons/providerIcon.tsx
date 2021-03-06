import { IconProps } from "@chakra-ui/react";
import React from "react";
import { Provider } from "../../utils/backend-client/types";
import { AWSIcon, GrantedKeysIcon, OktaIcon, AzureIcon } from "./Icons";

export const ProviderIcon = ({
  provider,
  ...rest
}: {
  provider: Provider | undefined;
} & IconProps): React.ReactElement => {
  if (provider === undefined) {
    // @ts-ignore
    return null;
  }
  switch (provider.type) {
    case "aws-sso":
      return <AWSIcon {...rest} />;
    case "okta":
      return <OktaIcon {...rest} />;
    case "azure-ad":
      return <AzureIcon {...rest} />;
    default:
      return <GrantedKeysIcon {...rest} />;
  }
};
