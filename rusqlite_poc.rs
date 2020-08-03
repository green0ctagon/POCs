use rusqlite::{Connection, OpenFlags, Result, NO_PARAMS};

fn main() -> Result<()> {
  let connection = Connection::open_with_flags("geoip_database", OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_SHARED_CACHE)?;
  let mut statement = connection.prepare("select latitude,longitude from records where start<=16797694 and end>=16797694;")?;
  let coordinates = statement.query_row(NO_PARAMS, |row| {
    Ok(Coordinates {
      latitude: row.get(0)?,
      longitude: row.get(1)?
    })
  })?;
  println!("{},{}",
    coordinates.latitude,
    coordinates.longitude
  );
  Ok(())
}

struct Coordinates {
  latitude: String,
  longitude: String
}
