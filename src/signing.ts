/**
 * Типы области подписи PDF и сохранение последних областей по документу.
 *
 * Координаты хранятся в миллиметрах от левого верхнего угла страницы: так их можно менять
 * при разном масштабе предпросмотра и отдавать в backend без пересчёта.
 */

export type StampRect = {
  /** Номер страницы, считая с нуля. */
  page: number;
  leftMm: number;
  topMm: number;
  widthMm: number;
  heightMm: number;
  /** Идентификатор сертификата, которому принадлежит область. */
  certificateId: string;
};

const STORAGE_KEY = 'cryptolite.stampRects';

type StoredRects = Record<string, StampRect[]>;

function readStore(): StoredRects {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as StoredRects;
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function documentKey(path: string, size: number): string {
  return `${path}#${size}`;
}

/** Области сохраняются до подписания: повторная подпись того же документа берёт те же места. */
export function loadStampRects(path: string, size: number): StampRect[] {
  const stored = readStore()[documentKey(path, size)];
  return Array.isArray(stored) ? stored : [];
}

export function saveStampRects(path: string, size: number, rects: StampRect[]) {
  try {
    const store = readStore();
    store[documentKey(path, size)] = rects;
    localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
  } catch {
    // Хранилище недоступно — это не ошибка подписи, места просто не запомнятся.
  }
}

export function forgetStampRects(path: string, size: number) {
  try {
    const store = readStore();
    delete store[documentKey(path, size)];
    localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
  } catch {
    // См. выше.
  }
}
