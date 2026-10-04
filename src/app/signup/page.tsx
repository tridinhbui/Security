import type { Metadata } from "next";
import { Suspense } from "react";
import { AuthForm } from "@/components/AuthForm";
export const metadata: Metadata = { title: "Đăng ký" };
export default function Page() { return <Suspense><AuthForm mode="signup" /></Suspense>; }
