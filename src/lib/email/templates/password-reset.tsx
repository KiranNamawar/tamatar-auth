import {
  Body,
  Button,
  Container,
  Head,
  Html,
  Link,
  Preview,
  Section,
  Text,
} from "@react-email/components";
import React from "react";

interface PasswordResetProps {
  firstName: string;
  resetUrl: string;
  expiresIn?: string;
}

export const PasswordResetTemplate = ({
  firstName = "User",
  resetUrl,
  expiresIn = "1 hour",
}: PasswordResetProps) => (
  <Html>
    <Head />
    <Preview>Reset your Tamatar account password</Preview>
    <Body style={main}>
      <Container style={container}>
        <Section style={coverSection}>
          <Section style={imageSection}>
            <Text style={logoText}>🍅 Tamatar</Text>
          </Section>
          <Section style={upperSection}>
            <Text style={h1}>Reset your password</Text>
            <Text style={mainText}>
              Hi {firstName}, we received a request to reset your password. 
              Click the button below to choose a new password for your account.
            </Text>
            <Section style={resetSection}>
              <Button href={resetUrl} style={button}>
                Reset Password
              </Button>
            </Section>
            <Text style={cautionText}>
              This password reset link will expire in {expiresIn}. If you didn't 
              request a password reset, you can safely ignore this email.
            </Text>
          </Section>
          <Section style={lowerSection}>
            <Text style={footerText}>
              If the button doesn't work, you can copy and paste this link:
            </Text>
            <Link href={resetUrl} style={link}>
              {resetUrl}
            </Link>
            <Text style={securityText}>
              For your security, this link can only be used once and will expire soon.
            </Text>
          </Section>
        </Section>
      </Container>
    </Body>
  </Html>
);

const main = {
  backgroundColor: "#fff",
  color: "#212121",
};

const container = {
  padding: "20px",
  margin: "0 auto",
  backgroundColor: "#eee",
};

const coverSection = {
  backgroundColor: "#fff",
  border: "1px solid #e0e0e0",
  borderRadius: "8px",
  overflow: "hidden",
};

const imageSection = {
  backgroundColor: "#252f3d",
  display: "flex",
  padding: "20px 0",
  alignItems: "center",
  justifyContent: "center",
};

const logoText = {
  fontSize: "24px",
  fontWeight: "bold",
  color: "#fff",
  textAlign: "center" as const,
};

const upperSection = {
  padding: "25px 35px",
};

const h1 = {
  color: "#333",
  fontFamily:
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif",
  fontSize: "20px",
  fontWeight: "bold",
  marginBottom: "15px",
};

const mainText = {
  color: "#333",
  fontFamily:
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif",
  fontSize: "14px",
  margin: "24px 0",
};

const resetSection = {
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  textAlign: "center" as const,
  margin: "30px 0",
};

const button = {
  backgroundColor: "#dc3545",
  borderRadius: "4px",
  color: "#fff",
  fontFamily:
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif",
  fontSize: "15px",
  textDecoration: "none",
  textAlign: "center" as const,
  display: "block",
  width: "200px",
  padding: "14px 7px",
};

const cautionText = {
  color: "#666",
  fontFamily:
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif",
  fontSize: "12px",
  lineHeight: "24px",
  margin: "0",
  textAlign: "center" as const,
};

const lowerSection = {
  padding: "25px 35px",
  backgroundColor: "#fafafa",
};

const footerText = {
  color: "#666",
  fontFamily:
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif",
  fontSize: "12px",
  lineHeight: "24px",
  textAlign: "center" as const,
  marginBottom: "10px",
};

const securityText = {
  color: "#666",
  fontFamily:
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif",
  fontSize: "11px",
  lineHeight: "20px",
  textAlign: "center" as const,
  marginTop: "15px",
  fontStyle: "italic",
};

const link = {
  color: "#dc3545",
  fontFamily:
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif",
  fontSize: "12px",
  textDecoration: "underline",
  textAlign: "center" as const,
  display: "block",
  wordBreak: "break-all" as const,
};

export default PasswordResetTemplate;
