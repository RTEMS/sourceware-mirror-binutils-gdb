/* A "next" iterator for GDB, the GNU debugger.
   Copyright (C) 2019-2026 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef GDBSUPPORT_NEXT_ITERATOR_H
#define GDBSUPPORT_NEXT_ITERATOR_H

#include "gdbsupport/iterator-range.h"

/* An iterator base class for iterating over a field of a type.  In order to
   form a functioning iterator, classes inheriting this should define an
   operator++, which determines the actual field that is iterated over.

   Instead of factoring out a base class, we could use something like this:

     template<typename T, auto F = &T::next>
     struct next_iterator
     {
       ...
       self_type &operator++ ()
       {
	 m_item = m_item->*F;
	 return *this;
       }
       ...
     }

  but that has the drawback that it doesn't work with incomplete T.  */

template<typename T>
struct base_next_iterator
{
  typedef base_next_iterator self_type;
  typedef T *value_type;
  typedef T *&reference;
  typedef T **pointer;
  typedef std::forward_iterator_tag iterator_category;
  typedef int difference_type;

  explicit base_next_iterator (T *item)
    : m_item (item)
  {
  }

  /* Create a one-past-the-end iterator.  */
  base_next_iterator ()
    : m_item (nullptr)
  {
  }

  value_type operator* () const
  {
    return m_item;
  }

  bool operator== (const self_type &other) const
  {
    return m_item == other.m_item;
  }

  bool operator!= (const self_type &other) const
  {
    return m_item != other.m_item;
  }

protected:

  T *m_item;
};

/* An iterator that uses the 'next' field of a type to iterate.  This
   can be used with various GDB types that are stored as linked
   lists.  */

template<typename T>
struct next_iterator : base_next_iterator<T> {
  typedef next_iterator self_type;
  typedef T *value_type;
  typedef T *&reference;
  typedef T **pointer;

  explicit next_iterator (T *item)
    : base_next_iterator<T> (item)
  {
  }

  next_iterator () = default;

  self_type &operator++ ()
  {
    this->m_item = this->m_item->next;
    return *this;
  }
};

/* A convenience wrapper to make a range type around a next_iterator.  */

template <typename T>
using next_range = iterator_range<next_iterator<T>>;

#endif /* GDBSUPPORT_NEXT_ITERATOR_H */
