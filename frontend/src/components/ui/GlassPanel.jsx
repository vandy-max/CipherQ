import clsx from "clsx";
import { motion } from "framer-motion";

/**
 * GlassPanel — CipherQ-styled frosted dark surface.
 *
 * Design reference: Stitch export (`glass-sidebar` / `matte-obsidian`
 * treatment in cipherq/DESIGN.md). Used for chrome-level surfaces
 * (sidebar, topbar) as those get migrated in later modules, and
 * anywhere else a dark glass surface is wanted on top of a light page.
 * Purely presentational — no data/business logic.
 */
export default function GlassPanel({
  children,
  className,
  as: Component = "div",
  animate = false,
  ...props
}) {
  const Wrapper = animate ? motion.div : Component;
  const motionProps = animate
    ? {
        initial: { opacity: 0, y: 8 },
        animate: { opacity: 1, y: 0 },
        transition: { duration: 0.28, ease: "easeOut" },
      }
    : {};

  return (
    <Wrapper
      {...motionProps}
      className={clsx("cq-glass rounded-cq-lg", className)}
      {...props}
    >
      {children}
    </Wrapper>
  );
}
