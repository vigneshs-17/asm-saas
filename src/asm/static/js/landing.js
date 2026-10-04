/**
 * Landing Page GSAP Animations (v3.5)
 * Strict requirements:
 * - Entrance reveals only (gsap.from + ScrollTrigger with once: true)
 * - NO pinning, NO scrub
 * - Transform and opacity only
 * - Fully wrapped in gsap.matchMedia for (prefers-reduced-motion: no-preference)
 * - No setAttribute('style'), no DOM html injection
 */

document.addEventListener("DOMContentLoaded", function () {
  if (typeof window.gsap === "undefined") {
    return;
  }

  var gsap = window.gsap;
  if (typeof window.ScrollTrigger !== "undefined") {
    gsap.registerPlugin(window.ScrollTrigger);
  }

  var mm = gsap.matchMedia();

  mm.add("(prefers-reduced-motion: no-preference)", function () {
    // 1. Hero Entrance Sequence
    var heroTl = gsap.timeline({ defaults: { ease: "power2.out" } });

    heroTl
      .from(".hero-copy > *", {
        y: 28,
        opacity: 0,
        stagger: 0.12,
        duration: 0.75,
      })
      .from(
        ".pipeline-stage-node",
        {
          y: 20,
          opacity: 0,
          stagger: 0.08,
          duration: 0.6,
        },
        "-=0.4"
      );

    // 2. Problem Section Entrance
    gsap.from(".problem-section .section-intro > *", {
      scrollTrigger: {
        trigger: ".problem-section",
        start: "top 80%",
        once: true,
      },
      y: 24,
      opacity: 0,
      stagger: 0.1,
      duration: 0.7,
      ease: "power2.out",
    });

    // 3. Pipeline Stages Cards Entrance
    gsap.from(".stage-step-card", {
      scrollTrigger: {
        trigger: ".stages-grid",
        start: "top 80%",
        once: true,
      },
      y: 30,
      opacity: 0,
      stagger: 0.12,
      duration: 0.65,
      ease: "power2.out",
    });

    // 4. Features Grid Entrance
    gsap.from(".feature-item", {
      scrollTrigger: {
        trigger: ".features-grid",
        start: "top 80%",
        once: true,
      },
      y: 25,
      opacity: 0,
      stagger: 0.08,
      duration: 0.6,
      ease: "power2.out",
    });

    // 5. Trust Card Entrance
    gsap.from(".trust-card", {
      scrollTrigger: {
        trigger: ".trust-section",
        start: "top 80%",
        once: true,
      },
      y: 25,
      opacity: 0,
      duration: 0.7,
      ease: "power2.out",
    });

    // 6. CTA Container Entrance
    gsap.from(".cta-container > *", {
      scrollTrigger: {
        trigger: ".cta-section",
        start: "top 85%",
        once: true,
      },
      y: 20,
      opacity: 0,
      stagger: 0.1,
      duration: 0.65,
      ease: "power2.out",
    });
  });
});
