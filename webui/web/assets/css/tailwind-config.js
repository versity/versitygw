/*
 * Copyright 2026 Versity Software
 * This file is licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

// Shared Tailwind CSS configuration for all pages.
// Edit this file to change the global color palette, typography, etc.
tailwind.config = {
  theme: {
    extend: {
      colors: {
        primary: {
          DEFAULT: '#002A7A',
          50: '#E6EBF4',
          100: '#B3C2E0',
          200: '#809ACC',
          300: '#4D71B8',
          400: '#264DA3',
          500: '#002A7A',
          600: '#002468',
          700: '#001D56',
        },
        accent: {
          DEFAULT: '#0076CD',
          50: '#E6F3FA',
          100: '#B3DCF2',
          500: '#0076CD',
          600: '#0065AF',
        },
        charcoal: {
          DEFAULT: '#191B2A',
          300: '#757884',
          400: '#565968',
        },
        surface: {
          DEFAULT: '#F3F8FC',
        }
      },
      fontFamily: {
        sans: ['Roboto', 'system-ui', 'sans-serif'],
      },
    }
  }
}
