import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { Suspense } from "react";
import { AuthForm } from "@/components/AuthForm";
import { getUser } from "@/lib/auth/next";
import { env } from "@/lib/env";

export const metadata: Metadata = { title: "Đăng ký" };
export const dynamic = "force-dynamic";

export default async function Page({ searchParams }: { searchParams: Promise<{ next?: string }> }) {
  // Đã đăng nhập thì không cần ở lại trang này.
  if (await getUser()) {
    const { next } = await searchParams;
    redirect(next && next.startsWith("/") && !next.startsWith("//") && !next.includes("\\") ? next : "/dashboard");
  }
  return <Suspense><AuthForm mode="signup" googleEnabled={env.googleEnabled} /></Suspense>;
}
