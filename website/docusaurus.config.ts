import type * as Preset from '@docusaurus/preset-classic';
import type { Config } from '@docusaurus/types';
import { themes as prismThemes } from 'prism-react-renderer';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const config: Config = {
  title: 'Gatepost',
  tagline: 'OIDC authentication for Traefik and ext_authz gateways',
  favicon: 'img/favicon.ico',

  // Origin only. Docusaurus rejects a url that contains a path, and this
  // site is not deployed anywhere yet.
  url: 'https://blackdark.github.io',
  baseUrl: '/',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'BlackDark', // Usually your GitHub org/user name.
  projectName: 'gatepost', // Usually your repo name.
  trailingSlash: false,

  onBrokenLinks: 'throw',

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl: 'https://github.com/BlackDark/gatepost/tree/main/website/',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themes: ['@docusaurus/theme-mermaid'],

  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownImages: 'warn',
      onBrokenMarkdownLinks: 'warn',
    },
  },

  themeConfig: {
    // Replace with your project's social card
    image: 'img/social-card.jpg',
    navbar: {
      title: 'Gatepost',
      logo: {
        alt: 'Gatepost',
        src: 'img/logo.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'gettingStartedSidebar',
          position: 'left',
          label: 'Getting Started',
        },
        {
          type: 'docSidebar',
          sidebarId: 'identityProvidersSidebar',
          position: 'left',
          label: 'Identity Providers',
        },
        {
          type: 'docSidebar',
          sidebarId: 'configSamplesSidebar',
          position: 'left',
          label: 'Config Samples',
        },
        {
          href: 'https://github.com/BlackDark/gatepost/discussions/categories/q-a',
          label: 'I have a Question',
          position: 'right',
        },
        {
          href: 'https://github.com/BlackDark/gatepost',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    docs: {
      sidebar: {
        hideable: true,
      },
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {
              label: 'Getting Started',
              to: '/docs/getting-started',
            },
            {
              label: 'Identity Providers',
              to: '/docs/identity-providers',
            },
            {
              label: 'Config Samples',
              to: '/docs/config-samples',
            },
          ],
        },
        {
          title: 'Support',
          items: [
            {
              label: 'Github Discussions',
              href: 'https://github.com/BlackDark/gatepost/discussions',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/BlackDark/gatepost',
            },
            {
              label: 'Sponsor',
              href: 'https://github.com/sponsors/sevensolutions',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} sevensolutions. Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
    mermaid: {
      //theme: { light: 'neutral', dark: 'forest' },
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
